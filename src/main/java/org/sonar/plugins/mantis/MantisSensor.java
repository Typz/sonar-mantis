/*
 * Sonar Mantis Plugin
 * Copyright (C) 2011 Jérémie Lagarde
 * dev@sonar.codehaus.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */

package org.sonar.plugins.mantis;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.*;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.Sensor;
import org.sonar.api.batch.SensorContext;
import org.sonar.api.config.Settings;
import org.sonar.api.measures.CountDistributionBuilder;
import org.sonar.api.measures.Measure;
import org.sonar.api.profiles.RulesProfile;
import org.sonar.api.resources.Project;
import org.sonar.api.rules.ActiveRule;
import org.sonar.api.rules.Rule;
import org.sonar.api.rules.Violation;
import org.sonar.api.utils.SonarException;
import org.sonar.plugins.mantis.soap.MantisSoapService;

import biz.futureware.mantis.rpc.soap.client.FilterData;
import biz.futureware.mantis.rpc.soap.client.IssueData;

/**
 * @author Jeremie Lagarde
 * @since 0.1
 */
public class MantisSensor implements Sensor {

  private static final Logger LOG = LoggerFactory.getLogger(MantisSensor.class);

  private String serverUrl;
  private String username;
  private String password;
  private String filterName;
  private Settings settings;
  private RulesProfile profile;

  private int oldAge = MantisRuleRepository.OLD_TICKET.getParam("age").getDefaultValueAsInteger();
  private int unassignedAge = MantisRuleRepository.UNASSIGNED_TICKET.getParam("age").getDefaultValueAsInteger();
  private int stalledAge = MantisRuleRepository.STALLED_TICKET.getParam("age").getDefaultValueAsInteger();
  private Set<String> selfAssignedStates = new HashSet<String>();

  public MantisSensor(Settings settings, RulesProfile profile) {
    this.settings = settings;
    this.profile = profile;

    List<ActiveRule> rules = profile.getActiveRulesByRepository(MantisRuleRepository.REPOSITORY_KEY);
    for (ActiveRule r: rules) {
      if (r.getRuleKey() == MantisRuleRepository.OLD_TICKET.getKey()) {
        oldAge = Integer.parseInt(r.getParameter("age"));
        LOG.info("old ticket age:" + oldAge);
      }
      else if (r.getRuleKey() == MantisRuleRepository.UNASSIGNED_TICKET.getKey()) {
        unassignedAge = Integer.parseInt(r.getParameter("age"));
        LOG.info("unassigned ticket age:" + unassignedAge);
      }
      else if (r.getRuleKey() == MantisRuleRepository.STALLED_TICKET.getKey()) {
        stalledAge = Integer.parseInt(r.getParameter("age"));
        LOG.info("stalled ticket age:" + stalledAge);
      }
      else if (r.getRuleKey() == MantisRuleRepository.SELF_ASSIGNED_TICKET.getKey()) {
        for (String s: r.getParameter("states").split(",")) {
          selfAssignedStates.add(s);
        }
        LOG.info("self assigned states:" + selfAssignedStates);
      }
    }

  }


  public String getServerUrl() {
    return serverUrl;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public String getFilterName() {
    return filterName;
  }

  public String getProjectName() {
    return projectName;
  }

  private String projectName;

  public void analyse(Project project, SensorContext context) {
    initParams(project);
    if (!isMandatoryParametersNotEmpty()) {
      LOG.warn("The server url, the project name, the filter name, the username and the password must not be empty.");
      return;
    }
    try {
      MantisSoapService service = createMantisSoapService();
      service.connect(username, password, projectName);
      analyze(project, context, service);
      service.disconnect();
    } catch (RemoteException e) {
      throw new SonarException("Error accessing Mantis web service, please verify the parameters", e);
    }
  }

  protected MantisSoapService createMantisSoapService() throws RemoteException {
    URL url;
    try {
      url = new URL(serverUrl + "/api/soap/mantisconnect.php");
    } catch (MalformedURLException e) {
      throw new SonarException("Error Mantis web service url \"" + serverUrl + "/api/soap/mantisconnect.php" + "\", please verify the parameters", e);
    }
    return new MantisSoapService(url);
  }

  private long daysElapsed(Date from, Date to)
  {
    return (to.getTime() - from.getTime()) / (24*3600*1000);
  }

  private void analyze(Project project, SensorContext context, MantisSoapService service) throws RemoteException {
    FilterData filter = null;
    if (getFilterName() != null) {
      FilterData[] filters = service.getFilters();
      for (FilterData f : filters) {
        if (getFilterName().equals(f.getName())) {
          filter = f;
        }
      }

      if (filter == null) {
        LOG.debug("Unable to find filter '{}' in Mantis for projectId {}", filterName, service.getProjectId());
        for (FilterData f : filters) {
          LOG.debug("   - {} : {}", f.getName(), f.getId());
        }
        throw new SonarException("Unable to find filter '" + filterName + "' in Mantis");
      }
    }

    IssueData[] issues = service.getIssues(filter);
    CountDistributionBuilder issuesByPriority = new CountDistributionBuilder(MantisMetrics.PRIORITIES);
    CountDistributionBuilder issuesByStatus = new CountDistributionBuilder(MantisMetrics.STATUS);
    CountDistributionBuilder issuesByDevelopers = new CountDistributionBuilder(MantisMetrics.DEVELOPERS);

    Date date = project.getAnalysisDate();
    if (date == null)
      date = new Date();  //current time

    for (IssueData issue : issues) {
      issuesByPriority.add(new MantisProperty(issue.getPriority()));
      issuesByStatus.add(new MantisProperty(issue.getStatus()));
      issuesByDevelopers.add(issue.getHandler() != null ? issue.getHandler().getName() : "unassigned");

      Rule rule = null;
      if (daysElapsed(issue.getDate_submitted().getTime(), date) >= oldAge) {
        rule = MantisRuleRepository.OLD_TICKET;
      }
      else if (issue.getHandler() == null &&
          daysElapsed(issue.getDate_submitted().getTime(), date) >= unassignedAge) {
        rule = MantisRuleRepository.UNASSIGNED_TICKET;
      }
      else if (daysElapsed(issue.getLast_updated().getTime(), date) >= stalledAge) {
        rule = MantisRuleRepository.STALLED_TICKET;
      }
      else if ((selfAssignedStates.isEmpty() || selfAssignedStates.contains(issue.getStatus().getName())) &&
          issue.getReporter() != null &&
          issue.getHandler() != null  &&
          issue.getReporter().getId() == issue.getHandler().getId()) {
        rule = MantisRuleRepository.SELF_ASSIGNED_TICKET;
      }

      if (rule != null) {
        LOG.info("Mantis #" + issue.getId() + ": " + rule.getName());
        context.saveViolation(Violation.create(rule, project)
            .setMessage("[#" + issue.getId() + "]" + issue.getSummary() + ": " + rule.getName()));
      }
    }

    saveMeasures(context, service.getProjectId(), new Measure(MantisMetrics.ISSUES).setIntValue(issues.length));
    saveMeasures(context, service.getProjectId(), issuesByPriority.build().setValue((double) issues.length));
    saveMeasures(context, service.getProjectId(), issuesByStatus.build().setValue((double) issues.length));
    saveMeasures(context, service.getProjectId(), issuesByDevelopers.build().setValue((double) issues.length));
  }

  protected void initParams(Project project) {
    serverUrl = settings.getString(MantisPlugin.SERVER_URL_PROPERTY);
    username = settings.getString(MantisPlugin.USERNAME_PROPERTY);
    password = settings.getString(MantisPlugin.PASSWORD_PROPERTY);
    filterName = settings.getString(MantisPlugin.FILTER_PROPERTY);
    projectName = settings.getString(MantisPlugin.PROJECTNAME_PROPERTY);
  }

  protected boolean isMandatoryParametersNotEmpty() {
    return StringUtils.isNotEmpty(serverUrl) && StringUtils.isNotEmpty(projectName)
      && StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password);
  }

  protected void saveMeasures(SensorContext context, BigInteger projectId, Measure issuesMeasure) {
    String url = serverUrl + "/search.php?project_id=" + projectId + "&sticky_issues=on&sortby=property&dir=DESC&hide_status_id=-2";
    issuesMeasure.setUrl(url);
    context.saveMeasure(issuesMeasure);
  }

  public boolean shouldExecuteOnProject(Project project) {
    return project.isRoot();
  }

  @Override
  public String toString() {
    return getClass().getSimpleName();
  }
}

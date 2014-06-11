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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.mockito.internal.stubbing.answers.CallsRealMethods;
import org.sonar.api.batch.SensorContext;
import org.sonar.api.config.Settings;
import org.sonar.api.measures.Measure;
import org.sonar.api.measures.Metric;
import org.sonar.api.profiles.RulesProfile;
import org.sonar.api.profiles.RulesProfileTest;
import org.sonar.api.resources.Project;
import org.sonar.api.resources.Resource;
import org.sonar.api.rules.Violation;
import org.sonar.plugins.mantis.soap.MantisSoapService;

import biz.futureware.mantis.rpc.soap.client.AccountData;
import biz.futureware.mantis.rpc.soap.client.FilterData;
import biz.futureware.mantis.rpc.soap.client.IssueData;
import biz.futureware.mantis.rpc.soap.client.MantisConnectLocator;
import biz.futureware.mantis.rpc.soap.client.MantisConnectPortType;
import biz.futureware.mantis.rpc.soap.client.ObjectRef;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

/**
 * @author Jeremie Lagarde
 * @since 0.1
 */
public class MantisSensorTest {

  private MantisSensor sensor;

  @Before
  public void setUp() throws Exception {
    final MantisSoapService service = new MantisSoapService(null) {

      @Override
      protected MantisConnectLocator createMantisConnectLocator() {
        MantisConnectLocator locator = mock(MantisConnectLocator.class);
        MantisConnectPortType portType = mock(MantisConnectPortType.class);
        String[] status = new String[] {"new", "feedback", "acknowledged", "confirmed", "assigned", "resolved", "validated", "closed"};
        String[] priorities = new String[] {"low", "normal", "high", "urgent", "immediate"};
        String[] users = new String[] {"user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9", "user10",
          "user11", "user12", "user13", "user14", "user15", "user16", "user17", "user18", "user19", "user20"};

        try {
          List<IssueData> issues = new ArrayList<IssueData>();
          for (int i = 0; i < 1000; i++) {
            IssueData issue = new IssueData();
            issue.setId(BigInteger.valueOf(i + 1));
            issue.setPriority(new ObjectRef(BigInteger.valueOf(i % 5), priorities[i % 5]));
            issue.setStatus(new ObjectRef(BigInteger.valueOf(i % 8), status[i % 8]));
            issue.setHandler(new AccountData(BigInteger.valueOf(i % 20), users[i % 20], users[i % 20], users[i % 20] + "@gmail.com"));
            issue.setDate_submitted(Calendar.getInstance());
            issue.setLast_updated(Calendar.getInstance());
            issues.add(issue);
          }
          FilterData filter = new FilterData(BigInteger.ONE, null, BigInteger.ONE, true, "current-version", "", "");
          when(locator.getMantisConnectPort()).thenReturn(portType);
          when(portType.mc_project_get_id_from_name("jer", "pwd", "myproject")).thenReturn(BigInteger.ONE);
          when(portType.mc_filter_get("jer", "pwd", BigInteger.ONE)).thenReturn(new FilterData[] {filter});
          when(portType.mc_filter_get_issues("jer", "pwd", BigInteger.ONE, filter.getId(), BigInteger.ONE, BigInteger.valueOf(50)))
              .thenReturn((IssueData[]) issues.toArray(new IssueData[issues.size()]));
        } catch (Exception e) {
          fail();
        }
        return locator;
      }
    };

    Settings settings = new Settings()
        .setProperty(MantisPlugin.SERVER_URL_PROPERTY, "http://localhost:1234/mantis/")
        .setProperty(MantisPlugin.USERNAME_PROPERTY, "jer")
        .setProperty(MantisPlugin.PASSWORD_PROPERTY, "pwd")
        .setProperty(MantisPlugin.PROJECTNAME_PROPERTY, "myproject")
        .setProperty(MantisPlugin.FILTER_PROPERTY, "current-version");
    RulesProfile rulesProfile = RulesProfile.create("test profile", "c++");
    sensor = new MantisSensor(settings, rulesProfile) {

      protected MantisSoapService createMantisSoapService() throws RemoteException {
        return service;
      }
    };
  }

  @Test
  public void testAnalyse() {
    SensorContext context = mock(MockSensorContext.class, new CallsRealMethods());
    Project project = mock(Project.class);
    sensor.analyse(project, context);
    assertThat(context.getMeasure(MantisMetrics.PRIORITIES).getValue(), is(Double.valueOf(1000)));
    assertThat(context.getMeasure(MantisMetrics.PRIORITIES).getData(), is("low=200;normal=200;high=200;urgent=200;immediate=200"));
    assertThat(context.getMeasure(MantisMetrics.STATUS).getValue(), is(Double.valueOf(1000)));
    assertThat(context.getMeasure(MantisMetrics.STATUS).getData(), is("new=125;feedback=125;acknowledged=125;confirmed=125;assigned=125;resolved=125;validated=125;closed=125"));
    assertThat(context.getMeasure(MantisMetrics.DEVELOPERS).getValue(), is(Double.valueOf(1000)));
    assertThat(
        context.getMeasure(MantisMetrics.DEVELOPERS).getData(),
        is("user1=50;user10=50;user11=50;user12=50;user13=50;user14=50;user15=50;user16=50;user17=50;user18=50;user19=50;user2=50;user20=50;user3=50;user4=50;user5=50;user6=50;user7=50;user8=50;user9=50"));
  }

  abstract class MockSensorContext implements SensorContext {

    @SuppressWarnings("rawtypes")
    Multimap<Resource, Measure> measures;
    Multimap<Resource, Violation> violations;

    @SuppressWarnings("rawtypes")
    private Multimap<Resource, Measure> getMeasures() {
      if (measures == null) {
        measures = ArrayListMultimap.create();
      }
      return measures;
    }

    private Multimap<Resource, Violation> getViolations() {
      if (violations == null) {
        violations = ArrayListMultimap.create();
      }
      return violations;
    }

    public boolean index(Resource r)
    {
      return true;
    }

    public void saveViolation(org.sonar.api.rules.Violation violation) {
      getViolations().put(violation.getResource(), violation);
    }

    public Measure saveMeasure(@SuppressWarnings("rawtypes") Resource resource, Measure measure) {
      getMeasures().put(resource, measure);
      return measure;
    }

    public Measure saveMeasure(Measure measure) {
      getMeasures().put(null, measure);
      return measure;
    }

    public Measure saveMeasure(Metric metric, Double value) {
      return saveMeasure(new Measure(metric, value));
    }

    public Measure getMeasure(@SuppressWarnings("rawtypes") Resource resource, Metric metric) {
      for (Measure measure : getMeasures().get(resource)) {
        if (measure.getMetric().equals(metric))
          return measure;
      }
      return null;
    }

    public Measure getMeasure(Metric metric) {
      return getMeasure(null, metric);
    }
  }
}

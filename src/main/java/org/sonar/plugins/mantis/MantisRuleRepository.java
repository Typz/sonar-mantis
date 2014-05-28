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

import com.google.common.collect.ImmutableList;
import org.sonar.api.rules.Rule;
import org.sonar.api.rules.RulePriority;
import org.sonar.api.rules.RuleRepository;

import java.util.List;

public class MantisRuleRepository extends RuleRepository {

  public static final String REPOSITORY_NAME = "Mantis";
  public static final String REPOSITORY_KEY = "mantis";

  //TODO: deal with bug severity!
  //      one rule for each bug priority
  // -OR- create violation with same priority as bug
  // -OR- configure the minimum priority in rule parameters
  //TODO: move description to resources?
  //TODO: check the 'type' for integers...
  //TODO: make the rules generic, i.e. for any language! --> like coverity? or there is a sonar-way?

  //Tickets open for a long time
  static final Rule OLD_TICKET = Rule.create(REPOSITORY_KEY, "mantis-old-ticket", REPOSITORY_NAME)
    .setSeverity(RulePriority.MAJOR)
    .setName("Old mantis ticket")
    .setDescription("Tickets that have been open for a long time.")
    .createParameter("age").setDescription("Maximum authorized age of an issue, in days.")
                           .setType("i")
                           .setDefaultValue("180")
                           .getRule();

  //Tickets unassigned after a time
  static final Rule UNASSIGNED_TICKET = Rule.create(REPOSITORY_KEY, "mantis-unassigned-ticket", REPOSITORY_NAME)
      .setSeverity(RulePriority.MAJOR)
      .setName("Unassigned mantis ticket")
      .setDescription("Tickets that have not been assigned quickly enough.")
      .createParameter("age").setDescription("Maximum authorized age of an unassigned issue, in days.")
                             .setType("i")
                             .setDefaultValue("7")
                             .getRule();

  //Tickets in not updated for some time
  static final Rule STALLED_TICKET = Rule.create(REPOSITORY_KEY, "mantis-stalled-ticket", REPOSITORY_NAME)
      .setSeverity(RulePriority.MAJOR)
      .setName("Stalled mantis ticket")
      .setDescription("Tickets that have not been updated for some time.")
      .createParameter("age").setDescription("Maximum time with no activity, in days.")
                             .setType("i")
                             .setDefaultValue("56")
                             .getRule();

  //Ticket assigned to reporter
  static final Rule SELF_ASSIGNED_TICKET = Rule.create(REPOSITORY_KEY, "mantis-self-assigned-ticket", REPOSITORY_NAME)
      .setSeverity(RulePriority.MAJOR)
      .setName("Self-assigned mantis ticket")
      .setDescription("Tickets that are assigned to reporter.")
      .createParameter("states").setDescription("Comma-separated list of states to consider. A violation will be generated " +
                                                "if a ticket is assigned to its reporter and the state is in this list." +
                                                "Leave empty to generate a violation in any case.")
                                .setType("s")
                                .setDefaultValue("new")
                                .getRule();

  public MantisRuleRepository() {
    super(REPOSITORY_KEY, "mantis");
    setName(REPOSITORY_NAME);
  }

  @Override
  public List<Rule> createRules() {
    return ImmutableList.of(OLD_TICKET, UNASSIGNED_TICKET, STALLED_TICKET, SELF_ASSIGNED_TICKET);
  }
}

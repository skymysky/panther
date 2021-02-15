/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';
import {
  buildPack,
  buildPackEnumeration,
  buildPolicy,
  buildRule,
  fireEvent,
  render,
  waitForElementToBeRemoved,
  within,
} from 'test-utils';
import { Route } from 'react-router-dom';
import urls from 'Source/urls';
import { mockGetPackDetails } from 'Pages/PackDetails/graphql/getPackDetails.generated';
import { mockEnumeratePack } from 'Pages/PackDetails/graphql/enumeratePack.generated';
import PackDetails from './PackDetails';

describe('PackDetails', () => {
  it('renders the pack details page', async () => {
    const pack = buildPack({
      displayName: 'Pack 1',
      description: 'This is an amazing description',
    });

    const mocks = [
      mockGetPackDetails({
        data: { pack },
        variables: {
          id: pack.id,
        },
      }),
      mockEnumeratePack({
        data: { enumeratePack: buildPackEnumeration() },
        variables: {
          id: pack.id,
        },
      }),
    ];

    const { getByText, getByTestId } = render(
      <Route exact path={urls.packs.details(':id')}>
        <PackDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.packs.details(pack.id)}`,
      }
    );
    const loadingInterfaceElement = getByTestId('pack-details-loading');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Rule info
    expect(getByText(pack.displayName)).toBeTruthy();
    expect(getByText(pack.description)).toBeTruthy();
    expect(getByText('Enabled')).toBeTruthy();
    // Tabs
    expect(getByText('Rules')).toBeTruthy();
    expect(getByText('Policies')).toBeTruthy();
    expect(getByText('Helpers')).toBeTruthy();
    expect(getByText('Data Models')).toBeTruthy();
  });

  it('shows the tabs as disabled when no alerts are in place', async () => {
    const pack = buildPack({
      displayName: 'Pack 1',
      description: 'This is an amazing description',
    });
    const mocks = [
      mockGetPackDetails({
        data: { pack },
        variables: {
          id: pack.id,
        },
      }),
      mockEnumeratePack({
        data: { enumeratePack: buildPackEnumeration({ globals: [], detections: [buildPolicy()] }) },
        variables: {
          id: pack.id,
        },
      }),
    ];

    const { getAllByTestId, getByTestId } = render(
      <Route exact path={urls.packs.details(':id')}>
        <PackDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.packs.details(pack.id)}`,
      }
    );

    const loadingInterfaceElement = getByTestId('pack-details-loading');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);
    const rulesTab = getAllByTestId('pack-rules');
    const policiesTab = getAllByTestId('pack-policies');
    const helpersTab = getAllByTestId('pack-helpers');
    const modelsTab = getAllByTestId('pack-models');

    const styleRules = window.getComputedStyle(rulesTab[0]);
    const stylePolicies = window.getComputedStyle(policiesTab[0]);
    const styleHelpers = window.getComputedStyle(helpersTab[0]);
    const styleModels = window.getComputedStyle(modelsTab[0]);

    expect(styleRules.opacity).toBe('0.5');
    expect(stylePolicies.opacity).toBe('1');
    expect(styleHelpers.opacity).toBe('0.5');
    expect(styleModels.opacity).toBe('1');
  });

  it('allows URL matching of tab navigation', async () => {
    const pack = buildPack({
      displayName: 'Pack 1',
      description: 'This is an amazing description',
    });
    const mocks = [
      mockGetPackDetails({
        data: { pack },
        variables: {
          id: pack.id,
        },
      }),
      mockEnumeratePack({
        data: { enumeratePack: buildPackEnumeration({ globals: [], detections: [buildPolicy()] }) },
        variables: {
          id: pack.id,
        },
      }),
    ];

    const { getByText, getByTestId, history } = render(
      <Route exact path={urls.packs.details(':id')}>
        <PackDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.packs.details(pack.id)}`,
      }
    );
    const loadingInterfaceElement = getByTestId('pack-details-loading');
    expect(loadingInterfaceElement).toBeTruthy();

    await waitForElementToBeRemoved(loadingInterfaceElement);
    fireEvent.click(getByText('Rules'));
    expect(history.location.search).toBe('?section=rules');
    fireEvent.click(getByText('Policies'));
    expect(history.location.search).toBe('?section=policies');
    fireEvent.click(getByText('Data Models'));
    expect(history.location.search).toBe('?section=models');
    fireEvent.click(getByText('Helpers'));
    expect(history.location.search).toBe('?section=helpers');
  });

  it('fetches and render rules and policies for the pack', async () => {
    const pack = buildPack({
      displayName: 'Pack 1',
      description: 'This is an amazing description',
    });
    const rule = buildRule();
    const policy = buildPolicy();

    const mocks = [
      mockGetPackDetails({
        data: { pack },
        variables: {
          id: pack.id,
        },
      }),
      mockEnumeratePack({
        data: { enumeratePack: buildPackEnumeration({ detections: [rule, policy] }) },
        variables: {
          id: pack.id,
        },
      }),
    ];

    const { getByText, getByTestId } = render(
      <Route exact path={urls.packs.details(':id')}>
        <PackDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.packs.details(pack.id)}`,
      }
    );
    const loadingInterfaceElement = getByTestId('pack-details-loading');
    expect(loadingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingInterfaceElement);
    fireEvent.click(getByText('Rules'));

    const withinTabPanel = within(getByTestId('pack-rules-tabpanel'));
    expect(withinTabPanel.getByText(rule.displayName)).toBeInTheDocument();
    expect(withinTabPanel.getByText('RULE')).toBeInTheDocument();

    expect(withinTabPanel.getByText('Log Types')).toBeInTheDocument();
    expect(withinTabPanel.getByText(rule.severity)).toBeInTheDocument();

    fireEvent.click(getByText('Policies'));
    const withinPoliciesTabPanel = within(getByTestId('pack-policies-tabpanel'));
    expect(withinPoliciesTabPanel.getByText(policy.displayName)).toBeInTheDocument();
    expect(withinPoliciesTabPanel.getByText('POLICY')).toBeInTheDocument();

    expect(withinPoliciesTabPanel.getByText('Resource Types')).toBeInTheDocument();
    expect(withinPoliciesTabPanel.getByText(policy.severity)).toBeInTheDocument();
  });

  it('fetches and render empty fallback for rules & policies', async () => {
    const pack = buildPack({
      displayName: 'Pack 1',
      description: 'This is an amazing description',
    });

    const mocks = [
      mockGetPackDetails({
        data: { pack },
        variables: {
          id: pack.id,
        },
      }),
      mockEnumeratePack({
        data: { enumeratePack: buildPackEnumeration({ detections: [] }) },
        variables: {
          id: pack.id,
        },
      }),
    ];

    const { getByText, getByTestId } = render(
      <Route exact path={urls.packs.details(':id')}>
        <PackDetails />
      </Route>,
      {
        mocks,
        initialRoute: `${urls.packs.details(pack.id)}`,
      }
    );
    const loadingInterfaceElement = getByTestId('pack-details-loading');
    expect(loadingInterfaceElement).toBeTruthy();
    await waitForElementToBeRemoved(loadingInterfaceElement);
    fireEvent.click(getByText('Rules'));

    const withinRulesTabPanel = within(getByTestId('pack-rules-tabpanel'));
    expect(withinRulesTabPanel.getByAltText('Empty Box Illustration')).toBeTruthy();

    fireEvent.click(getByText('Policies'));
    const withinPoliciesTabPanel = within(getByTestId('pack-policies-tabpanel'));
    expect(withinPoliciesTabPanel.getByAltText('Empty Box Illustration')).toBeTruthy();
  });
});

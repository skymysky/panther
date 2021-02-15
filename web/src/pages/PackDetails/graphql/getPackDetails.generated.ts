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

import * as Types from '../../../../__generated__/schema';

import { PackDetails } from '../../../graphql/fragments/PackDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetPackDetailsVariables = {
  id: Types.Scalars['ID'];
};

export type GetPackDetails = { pack: PackDetails };

export const GetPackDetailsDocument = gql`
  query GetPackDetails($id: ID!) {
    pack(id: $id) {
      ...PackDetails
    }
  }
  ${PackDetails}
`;

/**
 * __useGetPackDetails__
 *
 * To run a query within a React component, call `useGetPackDetails` and pass it any options that fit your needs.
 * When your component renders, `useGetPackDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetPackDetails({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useGetPackDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetPackDetails, GetPackDetailsVariables>
) {
  return ApolloReactHooks.useQuery<GetPackDetails, GetPackDetailsVariables>(
    GetPackDetailsDocument,
    baseOptions
  );
}
export function useGetPackDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetPackDetails, GetPackDetailsVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetPackDetails, GetPackDetailsVariables>(
    GetPackDetailsDocument,
    baseOptions
  );
}
export type GetPackDetailsHookResult = ReturnType<typeof useGetPackDetails>;
export type GetPackDetailsLazyQueryHookResult = ReturnType<typeof useGetPackDetailsLazyQuery>;
export type GetPackDetailsQueryResult = ApolloReactCommon.QueryResult<
  GetPackDetails,
  GetPackDetailsVariables
>;
export function mockGetPackDetails({
  data,
  variables,
  errors,
}: {
  data: GetPackDetails;
  variables?: GetPackDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetPackDetailsDocument, variables },
    result: { data, errors },
  };
}

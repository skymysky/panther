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
import { Flex, Icon, Text } from 'pouncejs';

interface DifferenceTextProps {
  diff: number;
}

const DifferenceText: React.FC<DifferenceTextProps> = ({ diff }) => {
  if (diff === 0) {
    return (
      <React.Fragment>
        <Text fontSize="small">No change</Text>
        <Flex>
          <Text fontSize="small">{diff}</Text>
        </Flex>
      </React.Fragment>
    );
  }
  if (diff > 0) {
    return (
      <React.Fragment>
        <Text fontSize="small">Decreased by</Text>
        <Flex>
          <Icon type="caret-down" size="small" color="green-400" />
          <Text fontSize="small">{diff}</Text>
        </Flex>
      </React.Fragment>
    );
  }

  return (
    <React.Fragment>
      <Text fontSize="small">Increased by</Text>
      <Flex>
        <Icon type="caret-up" size="small" color="red-300" />
        <Text fontSize="small">{-diff}</Text>
      </Flex>
    </React.Fragment>
  );
};

export default DifferenceText;

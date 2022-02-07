/**
 * ## Params
 *
 * - `ec2`: EC2 client
 * - `jp`: jsonpath
 * - `subnetId`
 * - `vpcId`: optional VPC Id
 *
 * ## Return
 *
 * ```
 * {
 *   type: 'any|cidr|no',
 *   cidr: [], // if type == 'cidr
 * }
 * ```
 */
async function checkSubnetIgw({ ec2, jp, subnetId, vpcId }) {
  let res = await getSubnetRouteTable({ ec2, jp, subnetId, vpcId });

  let igwCidr = jp.query(
    res.rt,
    `$.Routes[?(@.GatewayId.startsWith('igw-'))].DestinationCidrBlock`
  );

  if (igwCidr.length !== 0) {
    if (igwCidr.includes("0.0.0.0/0")) {
      return { type: "any" };
    } else {
      return { type: "cidr", cidr: igwCidr };
    }
  } else {
    return { type: "no" };
  }
}

/**
 * ## Params
 *
 * - `ec2`: EC2 client
 * - `jp`: jsonpath
 * - `subnetId`
 * - `vpcId`: optional VPC Id
 *
 * ## Return
 *
 * ```
 * {
 *   rt, // route table object in `describeRouteTables`
 * }
 * ```
 */
async function getSubnetRouteTable({ ec2, jp, subnetId, vpcId }) {
  let res;
  // find route table by subnet id
  res = await ec2.describeRouteTables({
    Filters: [{ Name: "association.subnet-id", Values: [subnetId] }],
  });

  if (res.RouteTables.length !== 0) {
    // route table explicitly associated with the subnet
    return { rt: res.RouteTables[0] };
  } else {
    // use VPC main route table
    if (!vpcId) {
      res = await ec2.describeSubnets({
        Filters: [{ Name: "subnet-id", Values: [subnetId] }],
      });
      vpcId = jp.query(res, `$..VpcId`)[0];
    }

    res = await ec2.describeRouteTables({
      Filters: [{ Name: "vpc-id", Values: [vpcId] }],
    });

    let routeTableId = jp.query(
      res,
      "$..Associations[?(@.Main)].RouteTableId"
    )[0];
    return {
      rt: jp.query(
        res,
        `$..RouteTables[?(@.RouteTableId=='${routeTableId}')]`
      )[0],
    };
  }
}

/**
 * ## Params
 *
 * - `ec2`: EC2 client
 * - `jp`: jsonpath
 * - `subnetId`
 * - `direction`: `'in'`/`'out'`
 * - `protocol`: protocol number(e.g. '17' means udp, '6' means tcp) or tcp/udp/icmp
 * - `port`: e.g. `22`
 *
 * ## Return
 *
 * ```
 * {
 *   any: false,
 *   rule: [{
 *     allow: true,
 *     cidr: '0.0.0.0/0',
 *     number: 100,
 *   }],
 * }
 * ```
 */
async function checkSubnetNacl({
  ec2,
  jp,
  subnetId,
  direction,
  protocol,
  port,
}) {
  // translate literal protocol to number
  switch (protocol) {
    case "tcp":
      protocol = "6";
      break;
    case "udp":
      protocol = "17";
      break;
    case "icmp":
      protocol = "1";
      break;
  }

  let res = await ec2.describeNetworkAcls({
    Filters: [{ Name: "association.subnet-id", Values: [subnetId] }],
  });

  return checkNacl({ jp, res, direction, protocol, port });
}

/**
 * ## Params
 *
 * - `jp`: jsonpath
 * - `res`: the response of `describeNetworkAcls`
 * - `direction`: `'in'`/`'out'`
 * - `protocol`: protocol number, e.g. '17' means udp, '6' means tcp
 * - `port`: e.g. `22`
 *
 * ## Return
 *
 * ```
 * {
 *   any: false,
 *   rule: [{
 *     allow: true,
 *     cidr: '0.0.0.0/0',
 *     number: 100,
 *   }],
 * }
 * ```
 */
function checkNacl({ jp, res, direction, protocol, port }) {
  let rules = jp
    .query(res, `$..Entries[?(${direction == "in" ? "!" : ""}@.Egress)]`)
    .filter((r) => {
      // filter protocol & port
      if (r.Protocol == "-1") {
        // any traffic
        return true;
      } else if (r.Protocol == protocol) {
        // icmp
        if (protocol == "1" && r.IcmpTypeCode.Type == port) {
          return true;
        } else if (r.PortRange.From <= port && r.PortRange.To >= port) {
          return true;
        }
      }
      return false;
    })
    .sort((a, b) => a.RuleNumber - b.RuleNumber);

  let result = {
    any: false,
    rule: [],
  };

  for (let i = 0; i < rules.length; i++) {
    const r = rules[i];
    result.rule.push({
      allow: r.RuleAction == "allow",
      cidr: r.CidrBlock,
      number: r.RuleNumber,
    });
  }

  if (result.rule.length > 0) {
    let r = result.rule[0];
    if (r.allow && r.cidr == "0.0.0.0/0") {
      result.any = true;
    }
  }

  return result;
}

export default {
  checkSubnetIgw,
  getSubnetRouteTable,
  checkSubnetNacl,
  checkNacl,
};

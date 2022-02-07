/**
 * ## Params
 *
 * - `ec2`: EC2 client
 * - `jp`: jsonpath
 * - `instanceIds`: A **list** of EC2 instance id
 * - `direction`: `'in'`/`'out'`
 * - `protocol`: e.g. `'tcp'`/`'udp'`/`'icmp'`
 * - `port`: e.g. `22`
 *
 * ## Return
 *
 * ```
 * {
 *   res, // the response of `describeSecurityGroups`
 *   securityGroupIds: [],
 *   anyTrafficPeer: {
 *     any: true,
 *     cidr: [],
 *     prefix: [],
 *     sg: [{
 *       UserId: '', // aws account id
 *       GroupId: '', // sg id
 *     }],
 *     no: false,
 *   },
 *   peer: {
 *     any: true,
 *     cidr: [],
 *     prefix: [],
 *     sg: [{
 *       UserId: '', // aws account id
 *       GroupId: '', // sg id
 *     }],
 *     no: false,
 *   },
 * }
 * ```
 */
async function checkEC2Instances({
  ec2,
  jp,
  instanceIds,
  direction,
  protocol,
  port,
}) {
  let securityGroupIds;
  let res = await ec2.describeInstances({ InstanceIds: instanceIds });
  securityGroupIds = jp.query(res, "$..SecurityGroups[*].GroupId");

  return {
    securityGroupIds,
    ...(await checkPort({
      ec2,
      jp,
      direction,
      securityGroupIds,
      protocol,
      port,
    })),
  };
}

/**
 * ## Params
 *
 * - `ec2`: EC2 client
 * - `jp`: jsonpath
 * - `direction`: `'in'`/`'out'`
 * - `securityGroupIds`: A **list** of security group id
 * - `protocol`: e.g. `'tcp'`/`'udp'`/`'icmp'`
 * - `port`: e.g. `22`
 *
 * ## Return
 *
 * ```
 * {
 *   res, // the response of `describeSecurityGroups`
 *   anyTrafficPeer: {
 *     any: true,
 *     cidr: [],
 *     prefix: [],
 *     sg: [{
 *       UserId: '', // aws account id
 *       GroupId: '', // sg id
 *     }],
 *     no: false,
 *   },
 *   peer: {
 *     any: true,
 *     cidr: [],
 *     prefix: [],
 *     sg: [{
 *       UserId: '', // aws account id
 *       GroupId: '', // sg id
 *     }],
 *     no: false,
 *   },
 * }
 * ```
 */
async function checkPort({
  ec2,
  jp,
  direction,
  securityGroupIds,
  protocol,
  port,
}) {
  let res = await ec2.describeSecurityGroups({
    GroupIds: securityGroupIds,
  });

  return {
    anyTrafficPeer: getPeer({ jp, res, direction, protocol: "-1" }),
    peer: getPeer({ jp, res, direction, protocol, port }),
    res,
  };
}

/**
 * ## Params
 *
 * - `ec2`: EC2 client
 * - `jp`: jsonpath
 * - `res`: the response of `describeSecurityGroups`
 * - `direction`: `'in'`/`'out'`
 * - `protocol`: `'tcp'`/`'ucp'`/`'icmp'`/`'-1'`(all)
 * - `port`
 *
 * ## Return
 *
 * ```
 * {
 *   any: true,
 *   cidr: [],
 *   prefix: [],
 *   sg: [{
 *     UserId: '', // aws account id
 *     GroupId: '', // sg id
 *   }],
 *   no: false,
 * }
 * ```
 */
function getPeer({ jp, res, direction, protocol, port }) {
  let result = {
    any: false,
    cidr: [],
    prefix: [],
    sg: [],
    no: true,
  };

  let portCondition =
    protocol == "-1"
      ? "true"
      : `(@.FromPort == -1 || (@.FromPort <= ${port} && (@.ToPort >= ${port} || @.ToPort == -1)))`;

  // get sg rules
  let ipPermissions = jp.query(
    res,
    `$..${
      direction == "in" ? "IpPermissions" : "IpPermissionsEgress"
    }[?(@.IpProtocol == '${protocol}' && ${portCondition})]`
  );

  if (ipPermissions.length == 0) return result;

  // get cidrs
  jp.query(ipPermissions, `$..CidrIp`).map((cidr) => {
    if (cidr == "0.0.0.0/0") {
      result.any = true;
    } else {
      result.cidr.push(cidr);
    }
    result.no = false;
  });

  // get prefix ids
  jp.query(ipPermissions, `$..PrefixListId`).map((prefix) => {
    result.prefix.push(prefix);
    result.no = false;
  });

  // get peer sgs
  jp.query(ipPermissions, `$..UserIdGroupPairs`)
    .flat()
    .map((userSgPair) => {
      result.sg.push(userSgPair);
      result.no = false;
    });

  return result;
}

export default {
  checkPort,
  getPeer,
  checkEC2Instances,
};

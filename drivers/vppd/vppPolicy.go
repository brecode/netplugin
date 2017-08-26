/***
Copyright 2017 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vppd

import (
	"strconv"

	"github.com/contiv/ofnet"
	log "github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/clientv1/linux/localclient"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"
	"google.golang.org/appengine/log"
)

// AddEndpointACL calls vpp-agent to apply ACL config to the endpoint
func AddEndpointACL(rule []*ofnet.OfnetPolicyRule, epGroupID int, afPacketName string) error {
	// Add Rule to the endpoint in VPP
	aclcfg := ACLConfig{}
	for id, vppRule := range rule {
		ruleID := vppRule.RuleId
		epPolicyIf := []string{afPacketName}

		action := getACLAction(vppRule.Action)
		matches := getACLMatches(vppRule)
		interfaces := getACLInterfaces(ruleID, epPolicyIf)

		aclcfg.acl = &vpp_acl.AccessLists_Acl{
			AclName: "acl-" + vppRule.RuleId[0:7] + "-id-" + strconv.Itoa(id) + "-" + afPacketName + "-" + ruleID[len(ruleID)-2:],
			Rules: []*vpp_acl.AccessLists_Acl_Rule{
				{
					RuleName: vppRule.RuleId,
					Actions:  action,
					Matches:  matches,
				},
			},
			Interfaces: interfaces,
		}
		err := localclient.DataChangeRequest(vppDriverID).
			Put().
			ACL(aclcfg.acl).
			Send().
			ReceiveReply()

		if err != nil {
			log.Errorf("Failed to create policy rule id=%s, Err: %v", vppRule.RuleId, err)
			return err
		}
	}
	return nil
}

// DelEndpointACL calls vpp-agent to delete ACL config from an endpoint
func DelEndpointACL(rule *ofnet.OfnetPolicyRule, id int, afPacketName string) error {
	// Delete ACL rule
	ruleID := rule.RuleId
	aclName := "acl-" + rule.RuleId[0:7] + "-id-" + strconv.Itoa(id) + "-" + afPacketName + "-" + ruleID[len(ruleID)-2:]
	err := localclient.DataChangeRequest(vppDriverID).
		Delete().
		ACL(aclName).
		Send().
		ReceiveReply()

	if err != nil {
		log.Errorf("Failed to delete policy rule id=%s, Err: %v", rule.RuleId, err)
		return err
	}
	return nil
}

func getACLAction(ruleAction string) (action *vpp_acl.AccessLists_Acl_Rule_Actions) {
	// Rule Action allow/deny mapping for vpp
	if ruleAction == "allow" || ruleAction == "ALLOW" {
		action = &vpp_acl.AccessLists_Acl_Rule_Actions{
			AclAction: vpp_acl.AclAction_PERMIT,
		}
	} else if ruleAction == "deny" || ruleAction == "DENY" {
		action = &vpp_acl.AccessLists_Acl_Rule_Actions{
			AclAction: vpp_acl.AclAction_DENY,
		}
	}
	return action
}

func getACLMatches(vppRule *ofnet.OfnetPolicyRule) (matches *vpp_acl.AccessLists_Acl_Rule_Matches) {
	var lowerDstPort, upperDstPort, lowerSrcPort, upperSrcPort uint32
	// Check if Port Range is zero
	if vppRule.DstPort == 0 {
		lowerDstPort = uint32(0)
		upperDstPort = uint32(65535)
	} else {
		lowerDstPort = uint32(vppRule.DstPort)
		upperDstPort = uint32(vppRule.DstPort)
	}
	if vppRule.SrcPort == 0 {
		lowerSrcPort = uint32(0)
		upperSrcPort = uint32(65535)
	} else {
		lowerSrcPort = uint32(vppRule.SrcPort)
		upperSrcPort = uint32(vppRule.SrcPort)
	}
	// Set Src/DstNetwork and Ports based on protocol
	if vppRule.IpProtocol == 6 {
		matches = &vpp_acl.AccessLists_Acl_Rule_Matches{
			IpRule: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule{
				Ip: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
					DestinationNetwork: vppRule.DstIpAddr,
					SourceNetwork:      vppRule.SrcIpAddr,
				},
				Tcp: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp{
					DestinationPortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
					SourcePortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Tcp_SourcePortRange{
						LowerPort: lowerSrcPort,
						UpperPort: upperSrcPort,
					},
				},
			},
		}
	} else if vppRule.IpProtocol == 17 {
		matches = &vpp_acl.AccessLists_Acl_Rule_Matches{
			IpRule: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule{
				Ip: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
					DestinationNetwork: vppRule.DstIpAddr,
					SourceNetwork:      vppRule.SrcIpAddr,
				},
				Udp: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp{
					DestinationPortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_DestinationPortRange{
						LowerPort: lowerDstPort,
						UpperPort: upperDstPort,
					},
					SourcePortRange: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Udp_SourcePortRange{
						LowerPort: lowerSrcPort,
						UpperPort: upperSrcPort,
					},
				},
			},
		}
	} else {
		matches = &vpp_acl.AccessLists_Acl_Rule_Matches{
			IpRule: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule{
				Ip: &vpp_acl.AccessLists_Acl_Rule_Matches_IpRule_Ip{
					DestinationNetwork: vppRule.DstIpAddr,
					SourceNetwork:      vppRule.SrcIpAddr,
				},
			},
		}
	}
	return matches
}

func getACLInterfaces(ruleID string, epPolicyIf []string) (interfaces *vpp_acl.AccessLists_Acl_Interfaces) {
	// Interface egress or ingress
	if ruleID[len(ruleID)-2:] == "Rx" {
		interfaces = &vpp_acl.AccessLists_Acl_Interfaces{
			Egress: epPolicyIf,
		}
	}
	if ruleID[len(ruleID)-2:] == "Tx" {
		interfaces = &vpp_acl.AccessLists_Acl_Interfaces{
			Ingress: epPolicyIf,
		}
	}
	return interfaces
}

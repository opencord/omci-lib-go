/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */

package generated

import "github.com/deckarep/golang-set"

// MacBridgePortConfigurationDataClassID is the 16-bit ID for the OMCI
// Managed entity MAC bridge port configuration data
const MacBridgePortConfigurationDataClassID = ClassID(47) // 0x002f

var macbridgeportconfigurationdataBME *ManagedEntityDefinition

// MacBridgePortConfigurationData (Class ID: #47 / 0x002f)
//	This ME models a port on a MAC bridge. Instances of this ME are created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME is linked to an instance of the MAC bridge service profile. Additional
//		bridge port control capabilities are provided by implicitly linked instances of some or all of:////		o	MAC bridge port filter table data;////		o	MAC bridge port filter pre-assign table;////		o	VLAN tagging filter data;////		o	Dot1 rate limiter.////		Real-time status of the bridge port is provided by implicitly linked instances of:////		o	MAC bridge port designation data;////		o	MAC bridge port bridge table data;////		o	Multicast subscriber monitor.////		Bridge port PM collection is provided by implicitly linked instances of:////		o	MAC bridge port PM history data;////		o	Ethernet frame PM history data upstream and downstream;////		o	Ethernet frame extended PM (preferred).
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. (R, setbycreate) (mandatory)
//			(2-bytes)
//
//		Bridge Id Pointer
//			This attribute points to an instance of the MAC bridge service profile. (R,-W, setbycreate)
//			(mandatory) (2-bytes)
//
//		Port Num
//			This attribute is the bridge port number. It must be unique among all ports associated with a
//			particular MAC bridge service profile. (R,-W, setbycreate) (mandatory) (1-byte)
//
//		Tp Type
//			This attribute identifies the type of TP associated with this MAC bridge port. Valid values are
//			as follows.
//
//			1	Physical path termination point Ethernet UNI
//
//			2	Interworking virtual circuit connection (VCC) termination point
//
//			3	IEEE 802.1p mapper service profile
//
//			4	IP host config data or IPv6 host config data
//
//			5	GEM interworking termination point
//
//			6	Multicast GEM interworking termination point
//
//			7	Physical path termination point xDSL UNI part 1
//
//			8	Physical path termination point VDSL UNI
//
//			9	Ethernet flow termination point
//
//			10	Reserved
//
//			11	Virtual Ethernet interface point
//
//			12	Physical path termination point MoCA UNI
//
//			13	Ethernet in the first mile (EFM) bonding group
//
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Tp Pointer
//			NOTE 1 - When the TP type is very high-speed digital subscriber line (VDSL) or xDSL, the two
//			MSBs may be used to indicate a bearer channel.
//
//			This attribute points to the TP associated with this MAC bridge port. The TP type attribute
//			indicates the type of the TP; this attribute contains its instance identifier (ME ID). (R,-W,
//			setbycreate) (mandatory) (2-bytes)
//
//		Port Priority
//			This attribute denotes the priority of the port for use in (rapid) spanning tree algorithms. The
//			range is 0..255. (R,-W, setbycreate) (optional) (2-bytes)
//
//		Port Path Cost
//			This attribute specifies the contribution of the port to the path cost towards the spanning tree
//			root bridge. The range is 1..65535. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Port Spanning Tree Ind
//			The Boolean value true enables (R)STP LAN topology change detection at this port. The value
//			false disables topology change detection. (R,-W, setbycreate) (mandatory) (1-byte)
//
//		Deprecated 1
//			This attribute is not used. If present, it should be ignored by both the ONU and the OLT, except
//			as necessary to comply with OMCI message definitions. (R,-W, setbycreate) (optional) (1-byte)
//
//		Deprecated 2
//			This attribute is not used. If present, it should be ignored by both the ONU and the OLT, except
//			as necessary to comply with OMCI message definitions. (R,-W, setbycreate) (1-byte) (optional)
//
//		Port Mac Address
//			If the TP associated with this port has a MAC address, this attribute specifies it. (R)
//			(optional) (6-bytes)
//
//		Outbound Td Pointer
//			This attribute points to a traffic descriptor that limits the traffic rate leaving the MAC
//			bridge. (R,-W) (optional) (2-byte)
//
//		Inbound Td Pointer
//			This attribute points to a traffic descriptor that limits the traffic rate entering the MAC
//			bridge. (R,-W) (optional) (2-byte)
//
//		Mac Learning Depth
//			This attribute specifies the maximum number of MAC addresses to be learned by this MAC bridge
//			port. The default value 0 specifies that there is no administratively imposed limit. (R,-W,
//			setbycreate) (optional) (1-byte)
//
//			NOTE 2 - If this attribute is not zero, its value overrides the value set in the MAC learning
//			depth attribute of the MAC bridge service profile.
//
//		Lasp Id Pointer
//			This attribute points to an instance of the LASP ME. (R,W, setbycreate) (optional) (2 bytes)
//
type MacBridgePortConfigurationData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const MacBridgePortConfigurationData_BridgeIdPointer = "BridgeIdPointer"
const MacBridgePortConfigurationData_PortNum = "PortNum"
const MacBridgePortConfigurationData_TpType = "TpType"
const MacBridgePortConfigurationData_TpPointer = "TpPointer"
const MacBridgePortConfigurationData_PortPriority = "PortPriority"
const MacBridgePortConfigurationData_PortPathCost = "PortPathCost"
const MacBridgePortConfigurationData_PortSpanningTreeInd = "PortSpanningTreeInd"
const MacBridgePortConfigurationData_Deprecated1 = "Deprecated1"
const MacBridgePortConfigurationData_Deprecated2 = "Deprecated2"
const MacBridgePortConfigurationData_PortMacAddress = "PortMacAddress"
const MacBridgePortConfigurationData_OutboundTdPointer = "OutboundTdPointer"
const MacBridgePortConfigurationData_InboundTdPointer = "InboundTdPointer"
const MacBridgePortConfigurationData_MacLearningDepth = "MacLearningDepth"
const MacBridgePortConfigurationData_LaspIdPointer = "LaspIdPointer"

func init() {
	macbridgeportconfigurationdataBME = &ManagedEntityDefinition{
		Name:    "MacBridgePortConfigurationData",
		ClassID: MacBridgePortConfigurationDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfffc,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  Uint16Field(MacBridgePortConfigurationData_BridgeIdPointer, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2:  ByteField(MacBridgePortConfigurationData_PortNum, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  ByteField(MacBridgePortConfigurationData_TpType, EnumerationAttributeType, 0x2000, 1, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4:  Uint16Field(MacBridgePortConfigurationData_TpPointer, PointerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5:  Uint16Field(MacBridgePortConfigurationData_PortPriority, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 5),
			6:  Uint16Field(MacBridgePortConfigurationData_PortPathCost, UnsignedIntegerAttributeType, 0x0400, 1, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 6),
			7:  ByteField(MacBridgePortConfigurationData_PortSpanningTreeInd, EnumerationAttributeType, 0x0200, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 7),
			8:  ByteField(MacBridgePortConfigurationData_Deprecated1, UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, true, 8),
			9:  ByteField(MacBridgePortConfigurationData_Deprecated2, UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, true, 9),
			10: MultiByteField(MacBridgePortConfigurationData_PortMacAddress, OctetsAttributeType, 0x0040, 6, toOctets("AAAAAAAA"), mapset.NewSetWith(Read), false, true, false, 10),
			11: Uint16Field(MacBridgePortConfigurationData_OutboundTdPointer, PointerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, Write), false, true, false, 11),
			12: Uint16Field(MacBridgePortConfigurationData_InboundTdPointer, PointerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, Write), false, true, false, 12),
			13: ByteField(MacBridgePortConfigurationData_MacLearningDepth, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 13),
			14: Uint16Field(MacBridgePortConfigurationData_LaspIdPointer, UnsignedIntegerAttributeType, 0x0004, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 14),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Port blocking",
		},
	}
}

// NewMacBridgePortConfigurationData (class ID 47) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewMacBridgePortConfigurationData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*macbridgeportconfigurationdataBME, params...)
}

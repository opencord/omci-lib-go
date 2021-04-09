/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 * Copyright 2020-present Open Networking Foundation

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

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

// TcpUdpConfigDataClassID is the 16-bit ID for the OMCI
// Managed entity TCP/UDP config data
const TcpUdpConfigDataClassID ClassID = ClassID(136)

var tcpudpconfigdataBME *ManagedEntityDefinition

// TcpUdpConfigData (class ID #136)
//	The TCP/UDP config data ME configures services based on the transmission control protocol (TCP)
//	and user datagram protocol (UDP) that are offered from an IP host. If a non-OMCI interface is
//	used to manage an IP service, this ME is unnecessary; the non-OMCI interface supplies the
//	necessary data.
//
//	An instance of this ME is created and deleted on request of the OLT.
//
//	Relationships
//		One or more instances of this ME may be associated with an instance of an IP host config data or
//		IPv6 host config data ME.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. It is
//			recommended that the ME ID be the same as the port number. (R, setbycreate) (mandatory)
//			(2-bytes)
//
//		Port Id
//			Port ID:	This attribute specifies the port number that offers the TCP/UDP service. (R,-W,
//			setbycreate) (mandatory) (2-bytes)
//
//		Protocol
//			Protocol:	This attribute specifies the protocol type as defined by [b-IANA] (protocol numbers),
//			for example UDP (0x11). (R,-W, setbycreate) (mandatory) (1-byte)
//
//		Tos_Diffserv Field
//			TOS/diffserv field: This attribute specifies the value of the TOS/diffserv field of the IPv4
//			header. The contents of this attribute may contain the type of service per [IETF RFC 2474] or a
//			DSCP. Valid values for DSCP are as defined by [b-IANA] (differentiated services field code
//			points). (R,-W, set-by-create) (mandatory) (1-byte)
//
//		Ip Host Pointer
//			IP host pointer: This attribute points to the IP host config data or IPv6 host config data ME
//			associated with this TCP/UDP data. Any number of ports and protocols may be associated with an
//			IP host. (R, W, set-by-create) (mandatory) (2 bytes)
//
type TcpUdpConfigData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	tcpudpconfigdataBME = &ManagedEntityDefinition{
		Name:    "TcpUdpConfigData",
		ClassID: 136,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xf000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: Uint16Field("PortId", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2: ByteField("Protocol", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: ByteField("TosDiffservField", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4: Uint16Field("IpHostPointer", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewTcpUdpConfigData (class ID 136) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTcpUdpConfigData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*tcpudpconfigdataBME, params...)
}

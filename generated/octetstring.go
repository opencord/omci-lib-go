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

// OctetStringClassID is the 16-bit ID for the OMCI
// Managed entity Octet string
const OctetStringClassID ClassID = ClassID(307)

var octetstringBME *ManagedEntityDefinition

// OctetString (class ID #307)
//	The octet string is modelled on the large string ME. The large string is constrained to
//	printable characters because it uses null as a trailing delimiter. The octet string has a length
//	attribute and is therefore suitable for arbitrary sequences of bytes.
//
//	Instances of this ME are created and deleted by the OLT. To use this ME, the OLT instantiates
//	the octet string ME and then points to the created ME from other ME instances. Systems that
//	maintain the octet string should ensure that the octet string ME is not deleted while it is
//	still linked.
//
//	Relationships
//		An instance of this ME may be cited by any ME that requires an octet string that can exceed
//		25-bytes in length.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. The values 0 and
//			0xFFFF are reserved. (R, setbycreate) (mandatory) (2-bytes)
//
//		Length
//			Length:	This attribute specifies the number of octets that comprise the sequence of octets. This
//			attribute defaults to 0 to indicate no octet string is defined. The maximum value of this
//			attribute is 375 (15 parts, 25-bytes each). (R,-W) (mandatory) (2-bytes)
//
//		Part 1, Part 2, Part 3, Part 4, Part 5, Part 6, Part 7, Part 8, Part 9, Part 10, Part 11, Part 12, Part 13, Part 14, Part 15
//			Part 1, Part 2, Part 3, Part 4, Part 5, Part 6, Part 7, Part 8, Part 9,  Part 10, Part 11, Part
//			12, Part 13, Part 14, Part 15:  (R,-W) (part 1 mandatory, others optional) (25-bytes * 15
//			attributes)
//
type OctetString struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	octetstringBME = &ManagedEntityDefinition{
		Name:    "OctetString",
		ClassID: 307,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xc000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: Uint16Field("Length", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2: MultiByteField("Part1,Part2,Part3,Part4,Part5,Part6,Part7,Part8,Part9,Part10,Part11,Part12,Part13,Part14,Part15", OctetsAttributeType, 0x4000, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, Write), false, false, false, 2),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewOctetString (class ID 307) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewOctetString(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*octetstringBME, params...)
}

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

// XdslPsdMaskProfileClassID is the 16-bit ID for the OMCI
// Managed entity xDSL PSD mask profile
const XdslPsdMaskProfileClassID = ClassID(110) // 0x006e

var xdslpsdmaskprofileBME *ManagedEntityDefinition

// XdslPsdMaskProfile (Class ID: #110 / 0x006e)
//	This ME contains a PSD mask profile for an xDSL UNI. An instance of this ME is created and
//	deleted by the OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of the PPTP xDSL UNI part
//		1.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The value 0 is reserved. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Psd Mask Table
//			This attribute is a table that defines the PSD mask applicable at the U-C2 reference point
//			(downstream) or the U-R2 reference point (upstream). This mask may impose PSD restrictions in
//			addition to the limit PSD mask defined in the relevant Recommendations ([ITUT G.992.3], [ITUT
//			G.992.5], [ITUT-G.993.2]).
//
//			NOTE - In [ITUT G.997.1], this attribute is called PSDMASKds (downstream) and PSDMASKus
//			(upstream). In [ITUT G.993.2], this attribute is called MIBMASKds (downstream) and MIBMASKus
//			(upstream). The ITU-T G.993.2 MIBMASKus does not include breakpoints to shape US0.
//
//			The PSD mask is specified through a set of breakpoints. Each breakpoint comprises a 2-byte
//			subcarrier index t, with a subcarrier spacing of 4.3125-kHz, and a 1-byte PSD mask level at that
//			subcarrier. The set of breakpoints can then be represented as [(t1, PSD1), (t2, PSD2), ..., (tN,
//			PSDN)]. The PSD mask level is coded as 0 (0.0-dBm/Hz) to 190  (-95.0-dBm/Hz), in steps of 0.5
//			dB.
//
//			The maximum number of downstream breakpoints is 32. In the upstream direction, the maximum
//			number of breakpoints is 4 for [ITU-T G.992.3] and 16 for [ITU-T G.993.2]. The requirements for
//			a valid set of breakpoints are defined in the relevant Recommendations ([ITUT G.992.3],
//			[ITUT-G.992.5], [ITUT G.993.2]).
//
//			Each table entry in this attribute comprises:
//
//			-	an entry number field (1-byte, first entry numbered 1);
//
//			-	a subcarrier index field, denoted t (2-bytes);
//
//			-	a PSD mask level field (1-byte).
//
//			By default, the PSD mask table is empty. Setting a subcarrier entry with a valid PSD mask level
//			implies insertion into the table or replacement of an existing entry. Setting an entry's PSD
//			mask level to 0xFF implies deletion from the table.
//
//			(R,-W) (mandatory) (4 * N bytes where N is the number of breakpoints)
//
//		Mask Valid
//			This Boolean attribute controls and reports the status of the PSD mask attribute.
//
//			As a status report, the value false indicates that the PSD mask represented in this ME has not
//			been impressed on the DSL equipment. The value true indicates that the PSD mask represented in
//			this ME has been impressed on the DSL equipment.
//
//			This attribute behaves as follows.
//
//			o	If the OLT changes any of the PSD mask table entries or sets mask valid false, then mask valid
//			is false.
//
//			o	If mask valid is false and the OLT sets mask valid true, the ONU impresses the PSD mask data
//			on the DSL equipment.
//
//			(R,-W) (mandatory) (1-byte)
//
type XdslPsdMaskProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const XdslPsdMaskProfile_PsdMaskTable = "PsdMaskTable"
const XdslPsdMaskProfile_MaskValid = "MaskValid"

func init() {
	xdslpsdmaskprofileBME = &ManagedEntityDefinition{
		Name:    "XdslPsdMaskProfile",
		ClassID: XdslPsdMaskProfileClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
			SetTable,
		),
		AllowedAttributeMask: 0xc000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: TableField(XdslPsdMaskProfile_PsdMaskTable, TableAttributeType, 0x8000, TableInfo{nil, 4}, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2: ByteField(XdslPsdMaskProfile_MaskValid, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, false, false, 2),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewXdslPsdMaskProfile (class ID 110) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXdslPsdMaskProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdslpsdmaskprofileBME, params...)
}

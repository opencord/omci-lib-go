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

// FastDataPathConfigurationProfileClassID is the 16-bit ID for the OMCI
// Managed entity FAST data path configuration profile
const FastDataPathConfigurationProfileClassID = ClassID(433) // 0x01b1

var fastdatapathconfigurationprofileBME *ManagedEntityDefinition

// FastDataPathConfigurationProfile (Class ID: #433 / 0x01b1)
//	This ME contains FAST the data path configuration profile for an xDSL UNI. An instance of this
//	ME is created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of the PPTP xDSL UNI part
//		1.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The value 0 is reserved. (R, set-
//			by-create) (mandatory) (2 bytes)
//
//		Tps_Tc Testmode Tps_Testmode
//			TPS-TC testmode (TPS_TESTMODE): This Boolean attribute specifies whether the TPSTC test mode
//			defined in clause 8.3.1 [ITU-T G.9701] is enabled (true) or disabled (disabled). See clause
//			7.3.1 of [ITUT-G.997.2]. (R,-W) (mandatory) (1 byte)
//
type FastDataPathConfigurationProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const FastDataPathConfigurationProfile_TpsTcTestmodeTpsTestmode = "TpsTcTestmodeTpsTestmode"

func init() {
	fastdatapathconfigurationprofileBME = &ManagedEntityDefinition{
		Name:    "FastDataPathConfigurationProfile",
		ClassID: FastDataPathConfigurationProfileClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0x8000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField(FastDataPathConfigurationProfile_TpsTcTestmodeTpsTestmode, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewFastDataPathConfigurationProfile (class ID 433) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewFastDataPathConfigurationProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*fastdatapathconfigurationprofileBME, params...)
}

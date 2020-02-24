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

// CardholderClassID is the 16-bit ID for the OMCI
// Managed entity Cardholder
const CardholderClassID ClassID = ClassID(5)

var cardholderBME *ManagedEntityDefinition

// Cardholder (class ID #5)
//	The cardholder represents the fixed equipment slot configuration of the ONU. Each cardholder can
//	contain 0 or 1 circuit packs; the circuit pack models equipment information that can change over
//	the lifetime of the ONU, e.g., through replacement.
//
//	One instance of this ME exists for each physical slot in an ONU that has pluggable circuit
//	packs. One or more instances of this ME may also exist in an integrated ONU, to represent
//	virtual slots. Instances of this ME are created automatically by the ONU, and the status
//	attributes are populated according to data within the ONU itself.
//
//	Slot 0 is intended to be used only in an integrated ONU. If an integrated ONU is modelled with a
//	universal slot 0, it is recommended that it does not contain additional (non-zero) virtual
//	slots. A cardholder for virtual slot 0 is recommended.
//
//	There is potential for conflict in the semantics of the expected plug-in unit type, the expected
//	port count and the expected equipment ID, both when the slot is not populated and when a new
//	circuit pack is inserted. The expected plug-in unit type and the plug-in type mismatch alarm are
//	mandatory, although plug-and-play/unknown (circuit pack type 255) may be used as a way to
//	minimize their significance. It is recommended that an ONU deny the provisioning of inconsistent
//	combinations of expected equipment attributes.
//
//	When a circuit pack is plugged into a cardholder or when a cardholder is pre-provisioned to
//	expect a circuit pack of a given type, it may trigger the ONU to instantiate a number of MEs and
//	update the values of others, depending on the circuit pack type. The ONU may also delete a
//	variety of other MEs when a circuit pack is reprovisioned to not expect a circuit pack or to
//	expect a circuit pack of a different type. These actions are described in the definitions of the
//	various MEs.
//
//	Expected equipment ID and expected port count are alternate ways to trigger the same
//	preprovisioning effects. These tools may be useful if an ONU is prepared to accept more than one
//	circuit pack of a given type but with different port counts, or if a circuit pack is a hybrid
//	that matches none of the types in Table 9.1.5-1, but whose identification (e.g., part number) is
//	known.
//
//	Relationships
//		An ONU may contain zero or more instances of the cardholder, each of which may contain an
//		instance of the circuit pack ME. The slot ID, real or virtual, is a fundamental identification
//		mechanism for MEs that bear some relationship to a physical location.
//
//	Attributes
//		Managed Entity Id
//			NOTE 1 - Some xDSL MEs use the two MSBs of the slot number for other purposes. An ONU that
//			supports these services may have slot limitations or restrictions.
//
//		Actual Plug In Unit Type
//			Actual plugin unit type: This attribute is equal to the type of the circuit pack in the
//			cardholder, or 0 if the cardholder is empty. When the cardholder is populated, this attribute is
//			the same as the type attribute of the corresponding circuit pack ME. Circuit pack types are
//			defined in Table 9.1.5-1. (R) (mandatory) (1-byte)
//
//		Expected Plug_In Unit Type
//			Expected plug-in unit type: This attribute provisions the type of circuit pack for the slot. For
//			type coding, see Table 9.1.5-1. The value 0 means that the cardholder is not provisioned to
//			contain a circuit pack. The value 255 means that the cardholder is configured for plug-and-play.
//			Upon ME instantiation, the ONU sets this attribute to 0. For integrated interfaces, this
//			attribute may be used to represent the type of interface. (R,-W) (mandatory) (1-byte)
//
//		Expected Port Count
//			Expected port count: This attribute permits the OLT to specify the number of ports it expects in
//			a circuit pack. Prior to provisioning by the OLT, the ONU initializes this attribute to 0.
//			(R,-W) (optional) (1-byte)
//
//		Expected Equipment Id
//			Expected equipment ID: This attribute provisions the specific type of expected circuit pack.
//			This attribute applies only to ONUs that do not have integrated interfaces. In some
//			environments, this may contain the expected CLEI code. Upon ME instantiation, the ONU sets this
//			attribute to all spaces. (R,-W) (optional) (20-bytes)
//
//		Actual Equipment Id
//			Actual equipment ID: This attribute identifies the specific type of circuit pack, once it is
//			installed. This attribute applies only to ONUs that do not have integrated interfaces. In some
//			environments, this may include the CLEI code. When the slot is empty or the equipment ID is not
//			known, this attribute should be set to all spaces. (R) (optional) (20-bytes)
//
//		Protection Profile Pointer
//			Protection profile pointer: This attribute specifies an equipment protection profile that may be
//			associated with the cardholder. Its value is the least significant byte of the ME ID of the
//			equipment protection profile with which it is associated, or 0 if equipment protection is not
//			used. (R) (optional) (1-byte)
//
//		Invoke Protection Switch
//			When circuit packs that support a PON interface (IF) function are switched, the response should
//			be returned on the same PON that received the command. However, the OLT should also be prepared
//			to accept a response on the redundant PON. (R,-W) (optional) (1-byte)
//
//		Alarm _ Reporting Control
//			Alarm-reporting control (ARC): See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			ARC interval: See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
type Cardholder struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	cardholderBME = &ManagedEntityDefinition{
		Name:    "Cardholder",
		ClassID: 5,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xff80,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField("ActualPlugInUnitType", EnumerationAttributeType, 0x8000, 0, mapset.NewSetWith(Read), true, false, false, 1),
			2: ByteField("ExpectedPlugInUnitType", EnumerationAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, false, false, 2),
			3: ByteField("ExpectedPortCount", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), false, true, false, 3),
			4: MultiByteField("ExpectedEquipmentId", StringAttributeType, 0x1000, 20, toOctets("ICAgICAgICAgICAgICAgICAgICA="), mapset.NewSetWith(Read, Write), false, true, false, 4),
			5: MultiByteField("ActualEquipmentId", StringAttributeType, 0x0800, 20, toOctets("ICAgICAgICAgICAgICAgICAgICA="), mapset.NewSetWith(Read), true, true, false, 5),
			6: ByteField("ProtectionProfilePointer", UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, true, false, 6),
			7: ByteField("InvokeProtectionSwitch", EnumerationAttributeType, 0x0200, 0, mapset.NewSetWith(Read, Write), false, true, false, 7),
			8: ByteField("AlarmReportingControl", EnumerationAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), true, true, false, 8),
			9: ByteField("ArcInterval", UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, Write), false, true, false, 9),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewCardholder (class ID 5) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewCardholder(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*cardholderBME, params...)
}

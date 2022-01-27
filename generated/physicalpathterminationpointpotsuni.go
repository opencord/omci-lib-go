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

// PhysicalPathTerminationPointPotsUniClassID is the 16-bit ID for the OMCI
// Managed entity Physical path termination point POTS UNI
const PhysicalPathTerminationPointPotsUniClassID = ClassID(53) // 0x0035

var physicalpathterminationpointpotsuniBME *ManagedEntityDefinition

// PhysicalPathTerminationPointPotsUni (Class ID: #53 / 0x0035)
//	This ME represents a POTS UNI in the ONU, where a physical path terminates and physical path
//	level functions (analogue telephony) are performed.
//
//	The ONU automatically creates an instance of this ME per port as follows.
//
//	o	When the ONU has POTS ports built into its factory configuration.
//
//	o	When a cardholder is provisioned to expect a circuit pack of the POTS type.
//
//	o	When a cardholder provisioned for plug-and-play is equipped with a circuit pack of the POTS
//	type. Note that the installation of a plug-and-play card may indicate the presence of POTS ports
//	via equipment ID as well as type, and indeed may cause the ONU to instantiate a port-mapping
//	package that specifies POTS ports.
//
//	The ONU automatically deletes instances of this ME when a cardholder is neither provisioned to
//	expect a POTS circuit pack, nor is it equipped with a POTS circuit pack.
//
//	Relationships
//		An instance of this ME is associated with each real or pre-provisioned POTS port. Either a SIP
//		or a VoIP voice CTP links to the POTS UNI. Status is available from a VoIP line status ME, and
//		RTP and call control PM may be collected on this point.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. This 2-byte number indicates the
//			physical position of the UNI. The first byte is the slot ID (defined in clause 9.1.5). The
//			second byte is the port ID, with the range 1..255. (R) (mandatory) (2-bytes)
//
//		Administrative State
//			When the administrative state is set to lock, all user functions of this UNI are blocked, and
//			alarms, TCAs and AVCs for this ME and all dependent MEs are no longer generated. Selection of a
//			default value for this attribute is outside the scope of this Recommendation. (R, W) (mandatory)
//			(1 byte)
//
//			This attribute shuts down (2), locks (1) and unlocks (0) the functions performed by this ME. If
//			the administrative state is set to shut down while the POTS UNI line state is non-idle, no
//			action is taken until the POTS UNI line state changes to idle, whereupon the administrative
//			state changes to locked. If the administrative state is set to shut down and the POTS UNI line
//			state is already idle, the administrative state is immediately set to locked. In both cases, the
//			transition from shutting down to locked state is signalled with an AVC.
//
//		Deprecated
//			This attribute is not used and should not be supported. (R,-W) (optional) (2-bytes)
//
//		Arc
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Impedance
//			2	C1=150 nF, R1=750 Ohm, R2=270 Ohm
//
//			3	C1=115 nF, R1=820 Ohm, R2=220 Ohm
//
//			4	C1=230 nF, R1=1050 Ohm, R2=320 Ohm
//
//			where C1, R1, and R2 are related as shown in Figure 9.9.1-1. Upon ME instantiation, the ONU sets
//			this attribute to 0. (R,-W) (optional) (1-byte)
//
//			This attribute specifies the impedance for the POTS UNI. Valid values include the following.
//
//			0	600 Ohm
//
//			1	900 Ohm
//
//			The following parameter sets from Annex C of [ETSI TS 101 270-1] are also defined:
//
//		Transmission Path
//			This attribute allows setting the POTS UNI either to full-time on-hook transmission (0) or part-
//			time on-hook transmission (1). Upon ME instantiation, the ONU sets this attribute to 0. (R,-W)
//			(optional) (1-byte)
//
//		Rx Gain
//			This attribute specifies a gain value for the received signal in the form of a 2s complement
//			number. Valid values are -120 (12.0-dB) to 60 (+6.0-dB). The direction of the affected signal is
//			in the D to A direction, towards the telephone set. Upon ME instantiation, the ONU sets this
//			attribute to 0. (R, W) (optional) (1 byte)
//
//		Tx Gain
//			This attribute specifies a gain value for the transmit signal in the form of a 2s complement
//			number. Valid values are -120 (12.0-dB) to 60 (+6.0-dB). The direction of the affected signal is
//			in the A to D direction, away from the telephone set. Upon ME instantiation, the ONU sets this
//			attribute to 0. (R, W) (optional) (1 byte)
//
//		Operational State
//			This attribute indicates whether the ME is capable of performing its function. Valid values are
//			enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Hook State
//			This attribute indicates the current state of the subscriber line: 0-= on hook, 1-= off hook (R)
//			(optional) (1-byte)
//
//		Pots Holdover Time
//			This attribute determines the time during which the POTS loop voltage is held up when a LOS or
//			softswitch connectivity is detected (please refer to the following table for description of
//			behaviours).. After the specified time elapses, the ONU drops the loop voltage, and may thereby
//			cause premises intrusion alarm or fire panel circuits to go active. When the ONU ranges
//			successfully on the PON or softswitch connectivity is restored, it restores the POTS loop
//			voltage immediately and resets the timer to zero. The attribute is expressed in seconds. The
//			default value 0 selects the vendor's factory policy. (R,-W) (optional) (2-bytes)
//
//		Nominal Feed Voltage
//			This attribute indicates the designed nominal feed voltage of the POTS loop. It is an absolute
//			value with resolution 1-V. This attribute does not represent the actual voltage measured on the
//			loop, which is available through the test command. (R,-W) (optional) (1-byte)
//
//		Loss Of Softswitch
//			This Boolean attribute controls whether the T/R holdover initiation criteria. False disables
//			loss of softswitch connectivity detection as criteria for initiating the POTS holdover timer.
//			True enables loss of softswitch connectivity detection as criteria for initiating the POTS
//			holdover timer. This attribute is optional (if not implemented, the POTS holdover time is
//			triggered on a LOS when POTS holdover is greater than zero). (R,-W) (optional) (1-byte)
//
type PhysicalPathTerminationPointPotsUni struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const PhysicalPathTerminationPointPotsUni_AdministrativeState = "AdministrativeState"
const PhysicalPathTerminationPointPotsUni_Deprecated = "Deprecated"
const PhysicalPathTerminationPointPotsUni_Arc = "Arc"
const PhysicalPathTerminationPointPotsUni_ArcInterval = "ArcInterval"
const PhysicalPathTerminationPointPotsUni_Impedance = "Impedance"
const PhysicalPathTerminationPointPotsUni_TransmissionPath = "TransmissionPath"
const PhysicalPathTerminationPointPotsUni_RxGain = "RxGain"
const PhysicalPathTerminationPointPotsUni_TxGain = "TxGain"
const PhysicalPathTerminationPointPotsUni_OperationalState = "OperationalState"
const PhysicalPathTerminationPointPotsUni_HookState = "HookState"
const PhysicalPathTerminationPointPotsUni_PotsHoldoverTime = "PotsHoldoverTime"
const PhysicalPathTerminationPointPotsUni_NominalFeedVoltage = "NominalFeedVoltage"
const PhysicalPathTerminationPointPotsUni_LossOfSoftswitch = "LossOfSoftswitch"

func init() {
	physicalpathterminationpointpotsuniBME = &ManagedEntityDefinition{
		Name:    "PhysicalPathTerminationPointPotsUni",
		ClassID: PhysicalPathTerminationPointPotsUniClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
			Test,
		),
		AllowedAttributeMask: 0xfff8,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  ByteField(PhysicalPathTerminationPointPotsUni_AdministrativeState, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), true, false, false, 1),
			2:  Uint16Field(PhysicalPathTerminationPointPotsUni_Deprecated, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, true, true, 2),
			3:  ByteField(PhysicalPathTerminationPointPotsUni_Arc, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), true, true, false, 3),
			4:  ByteField(PhysicalPathTerminationPointPotsUni_ArcInterval, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, true, false, 4),
			5:  ByteField(PhysicalPathTerminationPointPotsUni_Impedance, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, true, false, 5),
			6:  ByteField(PhysicalPathTerminationPointPotsUni_TransmissionPath, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, Write), false, true, false, 6),
			7:  ByteField(PhysicalPathTerminationPointPotsUni_RxGain, UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, Write), false, true, false, 7),
			8:  ByteField(PhysicalPathTerminationPointPotsUni_TxGain, UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), false, true, false, 8),
			9:  ByteField(PhysicalPathTerminationPointPotsUni_OperationalState, UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read), true, true, false, 9),
			10: ByteField(PhysicalPathTerminationPointPotsUni_HookState, UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, true, false, 10),
			11: Uint16Field(PhysicalPathTerminationPointPotsUni_PotsHoldoverTime, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, Write), false, true, false, 11),
			12: ByteField(PhysicalPathTerminationPointPotsUni_NominalFeedVoltage, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, Write), false, true, false, 12),
			13: ByteField(PhysicalPathTerminationPointPotsUni_LossOfSoftswitch, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read, Write), false, true, false, 13),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewPhysicalPathTerminationPointPotsUni (class ID 53) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewPhysicalPathTerminationPointPotsUni(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*physicalpathterminationpointpotsuniBME, params...)
}

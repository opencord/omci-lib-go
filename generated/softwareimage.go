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

package generated

import "github.com/deckarep/golang-set"

// SoftwareImageClassID is the 16-bit ID for the OMCI
// Managed entity Software image
const SoftwareImageClassID ClassID = ClassID(7)

var softwareimageBME *ManagedEntityDefinition

// SoftwareImage (class ID #7)
//	This ME models an executable software image stored in the ONU (documented here as its
//	fundamental usage). It may also be used to represent an opaque vendor-specific file
//	(vendorspecific usage).
//
//	Fundamental usage
//
//	The ONU automatically creates two instances of this ME upon the creation of each ME that
//	contains independently manageable software, either the ONU itself or an individual circuit pack.
//	It populates ME attributes according to data within the ONU or the circuit pack.
//
//	Some pluggable equipment may not contain software. Others may contain software that is
//	intrinsically bound to the ONU's own software image. No software image ME need exist for such
//	equipment, though it may be convenient for the ONU to create them to support software version
//	audit from the OLT. In this case, the dependent MEs would support only the get action.
//
//	A slot may contain various equipment over its lifetime, and if software image MEs exist, the ONU
//	must automatically create and delete them as the equipped configuration changes. The identity of
//	the software image is tied to the cardholder.
//
//	When an ONU controller packs are duplicated, each can be expected to contain two software image
//	MEs, managed through reference to the individual controller packs themselves. When this occurs,
//	the ONU should not have a global pair of software images MEs (instance 0), since an action
//	(download, activate, commit) directed to instance 0 would be ambiguous.
//
//	Relationships
//		Two instances of the software image ME are associated with each instance of the ONU or
//		cardholder whose software is independently managed.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. The first byte
//			indicates the physical location of the equipment hosting the software image, either the ONU (0)
//			or a cardholder (1..254). The second byte distinguishes between the two software image ME
//			instances (0..1). (R) (mandatory) (2-bytes)
//
//		Version
//			Version:	This string attribute identifies the version of the software. (R) (mandatory)
//			(14-bytes)
//
//		Is Committed
//			Is committed: This attribute indicates whether the associated software image is committed (1) or
//			uncommitted (0). By definition, the committed software image is loaded and executed upon reboot
//			of the ONU or circuit pack. During normal operation, one software image is always committed,
//			while the other is uncommitted. Under no circumstances are both software images allowed to be
//			committed at the same time. On the other hand, both software images could be uncommitted at the
//			same time if both were invalid. Upon ME instantiation, instance 0 is initialized to committed,
//			while instance 1 is initialized to uncommitted (i.e., the ONU ships from the factory with image
//			0 committed). (R) (mandatory) (1-byte)
//
//		Is Active
//			Is active:	This attribute indicates whether the associated software image is active (1) or
//			inactive (0). By definition, the active software image is one that is currently loaded and
//			executing in the ONU or circuit pack. Under normal operation, one software image is always
//			active while the other is inactive. Under no circumstances are both software images allowed to
//			be active at the same time. On the other hand, both software images could be inactive at the
//			same time if both were invalid. (R) (mandatory) (1-byte)
//
//		Is Valid
//			Is valid:	This attribute indicates whether the associated software image is valid (1) or invalid
//			(0). By definition, a software image is valid if it has been verified to be an executable code
//			image. The verification mechanism is not subject to standardization; however, it should include
//			at least a data integrity check [e.g., a cyclic redundancy check (CRC)] of the entire code
//			image. Upon ME instantiation or software download completion, the ONU validates the associated
//			code image and sets this attribute according to the result. (R) (mandatory) (1-byte)
//
//		Product Code
//			Product code:	This attribute provides a way for a vendor to indicate product code information on
//			a file. It is a character string, padded with trailing nulls if it is shorter than 25 bytes. (R)
//			(optional) (25 bytes)
//
//		Image Hash
//			Image hash:	This attribute is an MD5 hash of the software image. It is computed at completion of
//			the end download action. (R) (optional) (16-bytes)
//
type SoftwareImage struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	softwareimageBME = &ManagedEntityDefinition{
		Name:    "SoftwareImage",
		ClassID: 7,
		MessageTypes: mapset.NewSetWith(
			ActivateSoftware,
			CommitSoftware,
			DownloadSection,
			EndSoftwareDownload,
			Get,
			StartSoftwareDownload,
		),
		AllowedAttributeMask: 0xfc00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: MultiByteField("Version", StringAttributeType, 0x8000, 14, toOctets("ICAgICAgICAgICAgICA="), mapset.NewSetWith(Read), true, false, false, 1),
			2: ByteField("IsCommitted", EnumerationAttributeType, 0x4000, 0, mapset.NewSetWith(Read), true, false, false, 2),
			3: ByteField("IsActive", EnumerationAttributeType, 0x2000, 0, mapset.NewSetWith(Read), true, false, false, 3),
			4: ByteField("IsValid", EnumerationAttributeType, 0x1000, 0, mapset.NewSetWith(Read), true, false, false, 4),
			5: MultiByteField("ProductCode", OctetsAttributeType, 0x0800, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), true, true, false, 5),
			6: MultiByteField("ImageHash", StringAttributeType, 0x0400, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), true, true, false, 6),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewSoftwareImage (class ID 7) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewSoftwareImage(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*softwareimageBME, params...)
}

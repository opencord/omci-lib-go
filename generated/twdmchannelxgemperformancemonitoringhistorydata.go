/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
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

// TwdmChannelXgemPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity TWDM channel XGEM performance monitoring history data
const TwdmChannelXgemPerformanceMonitoringHistoryDataClassID ClassID = ClassID(445)

var twdmchannelxgemperformancemonitoringhistorydataBME *ManagedEntityDefinition

// TwdmChannelXgemPerformanceMonitoringHistoryData (class ID #445)
//	This ME collects certain XGEM-related PM data associated with the slot/circuit pack, hosting one
//	or more ANI-G MEs, for a specific TWDM channel. Instances of this ME are created and deleted by
//	the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of TWDM channel ME.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the TWDM channel ME. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1-byte)
//
//		Threshold Data 64 Bit Id
//			Threshold data 64-bit ID: This attribute points to an instance of the threshold data 64-bit ME
//			that contains PM threshold values. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Total Transmitted Xgem Frames
//			Total transmitted XGEM frames: The counter aggregated across all XGEM ports of the given ONU.
//			(R) (mandatory) (8-byte)
//
//		Transmitted Xgem Frames With Lf Bit Not Set
//			Transmitted XGEM frames with LF bit not set: The counter aggregated across all XGEM ports of the
//			given ONU identifies the number of fragmentation operations. (R) (mandatory) (8-byte)
//
//		Total Received Xgem Frames
//			Total received XGEM frames: The counter aggregated across all XGEM ports of the given ONU. (R)
//			(mandatory) (8-byte)
//
//		Received Xgem Frames With Xgem Header Hec Errors
//			Received XGEM frames with XGEM header HEC errors: The counter aggregated across all XGEM ports
//			of the given ONU identifies the number of loss XGEM frame delineation events. (R) (mandatory)
//			(8-byte)
//
//		Fs Words Lost To Xgem Header Hec Errors
//			FS words lost to XGEM header HEC errors: The counter of the FS frame words lost due to XGEM
//			frame header errors that cause loss of XGEM frame delineation. (R) (mandatory) (8-byte)
//
//		Xgem Encryption Key Errors
//			XGEM encryption key errors: The counter aggregated across all XGEM ports of the given ONU
//			identifies the number of received XGEM frames that have to be discarded because of unknown or
//			invalid encryption key. The number is included into the Total received XGEM frame count above.
//			(R) (mandatory) (8-byte)
//
//		Total Transmitted Bytes In Non_Idle Xgem Frames
//			Total transmitted bytes in non-idle XGEM frames: The counter aggregated across all XGEM ports of
//			the given. (R) (mandatory) (8-byte)
//
//		Total Received Bytes In Non_Idle Xgem Frames
//			Total received bytes in non-idle XGEM frames: The counter aggregated across all XGEM ports of
//			the given ONU. (R) (mandatory) (8-byte)
//
type TwdmChannelXgemPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	twdmchannelxgemperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "TwdmChannelXgemPerformanceMonitoringHistoryData",
		ClassID: 445,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetCurrentData,
			Set,
		),
		AllowedAttributeMask: 0xffc0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field("ThresholdData64BitId", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint64Field("TotalTransmittedXgemFrames", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint64Field("TransmittedXgemFramesWithLfBitNotSet", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint64Field("TotalReceivedXgemFrames", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint64Field("ReceivedXgemFramesWithXgemHeaderHecErrors", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint64Field("FsWordsLostToXgemHeaderHecErrors", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint64Field("XgemEncryptionKeyErrors", CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint64Field("TotalTransmittedBytesInNonIdleXgemFrames", CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint64Field("TotalReceivedBytesInNonIdleXgemFrames", CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewTwdmChannelXgemPerformanceMonitoringHistoryData (class ID 445) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTwdmChannelXgemPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*twdmchannelxgemperformancemonitoringhistorydataBME, params...)
}
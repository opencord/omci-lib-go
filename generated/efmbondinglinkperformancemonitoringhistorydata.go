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

// EfmBondingLinkPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity EFM bonding link performance monitoring history data
const EfmBondingLinkPerformanceMonitoringHistoryDataClassID ClassID = ClassID(423)

var efmbondinglinkperformancemonitoringhistorydataBME *ManagedEntityDefinition

// EfmBondingLinkPerformanceMonitoringHistoryData (class ID #423)
//	This ME collects PM data as seen at the xTU-C. Instances of this ME are created and deleted by
//	the OLT.
//
//	Relationships
//		An instance of this ME is associated with an xDSL UNI.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the EFM bonding link. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 and 2 MEs
//			that contain PM threshold values. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Rx Errored Fragments
//			Rx errored fragments: Clause 45.2.3.29 of [IEEE 802.3]. (R) (mandatory) (4-bytes)
//
//		Rx Small Fragments
//			Rx small fragments: Clause 45.2.3.30 of [IEEE 802.3]. (R) (mandatory) (4-bytes)
//
//		Rx Large Fragments
//			Rx large fragments: Clause 45.2.3.31 of [IEEE 802.3]. (R) (mandatory) (4-bytes)
//
//		Rx Discarded Fragments
//			Rx discarded fragments: Clause 45.2.3.32 of [IEEE 802.3]. (R) (mandatory) (4-bytes)
//
//		Rx Fcs Errors
//			Rx FCS errors: Clause 45.2.6.11 of [IEEE 802.3]. (R) (mandatory) (4-bytes)
//
//		Rx Coding Errors
//			Rx coding errors: Clause 45.2.6.12 of [IEEE 802.3]. (R) (mandatory) (4-bytes)
//
//		Rx Fragments
//			Rx fragments: Number of fragments received over this link. (R) (mandatory) (4-bytes)
//
//		Tx Fragments
//			Tx fragments: Number of fragments transmitted over this link. (R) (mandatory) (4-bytes)
//
type EfmBondingLinkPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	efmbondinglinkperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "EfmBondingLinkPerformanceMonitoringHistoryData",
		ClassID: 423,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xffc0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field("RxErroredFragments", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint32Field("RxSmallFragments", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field("RxLargeFragments", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint32Field("RxDiscardedFragments", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field("RxFcsErrors", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint32Field("RxCodingErrors", CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint32Field("RxFragments", CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field("TxFragments", CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewEfmBondingLinkPerformanceMonitoringHistoryData (class ID 423) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewEfmBondingLinkPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*efmbondinglinkperformancemonitoringhistorydataBME, params...)
}

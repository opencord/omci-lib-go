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

// FecPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity FEC performance monitoring history data
const FecPerformanceMonitoringHistoryDataClassID = ClassID(312) // 0x0138

var fecperformancemonitoringhistorydataBME *ManagedEntityDefinition

// FecPerformanceMonitoringHistoryData (Class ID: #312 / 0x0138)
//	This ME collects PM data associated with PON downstream forward error correction (FEC) counters.
//	Instances of this ME are created and deleted by the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of the ANI-G ME or an instance of the time
//		and wavelength division multiplexing (TWDM) channel ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the ANI-G or a TWDM channel. (R, setbycreate) (mandatory)
//			(2-bytes)
//
//		Interval End Time
//			This attribute identifies the most recently finished 15-min interval. (R) (mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 ME that
//			contains PM threshold values. Since no threshold value attribute number exceeds 7, a threshold
//			data 2 ME is optional. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Corrected Bytes
//			This attribute counts the number of bytes that were corrected by the FEC function. (R)
//			(mandatory) (4-bytes)
//
//		Corrected Code Words
//			This attribute counts the code words that were corrected by the FEC function. (R) (mandatory)
//			(4-bytes)
//
//		Uncorrectable Code Words
//			This attribute counts errored code words that could not be corrected by the FEC function. (R)
//			(mandatory) (4-bytes)
//
//		Total Code Words
//			This attribute counts the total received code words. (R) (mandatory) (4-bytes)
//
//		Fec Seconds
//			This attribute counts seconds during which there was an FEC anomaly. (R) (mandatory) (2-bytes)
//
type FecPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	fecperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "FecPerformanceMonitoringHistoryData",
		ClassID: 312,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xfe00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: Uint16Field("ThresholdData12Id", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint32Field("CorrectedBytes", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4: Uint32Field("CorrectedCodeWords", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5: Uint32Field("UncorrectableCodeWords", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6: Uint32Field("TotalCodeWords", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7: Uint16Field("FecSeconds", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Corrected bytes",
			1: "Corrected code words",
			2: "Uncorrectable code words",
			4: "FEC seconds",
		},
	}
}

// NewFecPerformanceMonitoringHistoryData (class ID 312) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewFecPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*fecperformancemonitoringhistorydataBME, params...)
}

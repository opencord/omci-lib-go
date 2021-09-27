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

package omci_test

import (
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go"
	me "github.com/opencord/omci-lib-go/generated"
	"github.com/stretchr/testify/assert"
	"testing"
)

var relaxDecodeSupportedResponses = []me.MsgType{
	// me.Get,
	me.MibUploadNext,
}

func canRelax(arr []me.MsgType, msgType me.MsgType) bool {
	for _, item := range arr {
		if item == msgType {
			return true
		}
	}
	return false
}

func TestAllTypesRelaxedDecodeSupport(t *testing.T) {
	// Requests (none are supported yet)
	for _, msgType := range allMsgTypes {
		assert.Error(t, me.SetRelaxedDecode(msgType, true, true))
		assert.False(t, me.GetRelaxedDecode(msgType, true))
	}
	// Responses (only a couple are supported at this time)
	for _, msgType := range allMsgTypes {

		if canRelax(relaxDecodeSupportedResponses, msgType) {
			// Default is True if it is supported
			assert.True(t, me.GetRelaxedDecode(msgType, false))

			// Set False
			assert.NoError(t, me.SetRelaxedDecode(msgType, false, false))
			assert.False(t, me.GetRelaxedDecode(msgType, false))

			// Set back to True
			assert.NoError(t, me.SetRelaxedDecode(msgType, false, true))
			assert.True(t, me.GetRelaxedDecode(msgType, false))
		} else {
			// Default is False
			assert.False(t, me.GetRelaxedDecode(msgType, false))
			assert.Error(t, me.SetRelaxedDecode(msgType, false, true))
			assert.Error(t, me.SetRelaxedDecode(msgType, false, false))
		}
	}
}

// TestMibUploadNextResponseRelaxedDecode will decode a frame with 'new' unknown
// attributes at the end (fake ones for this test) and should fail. Then it will
// enable relax decode and should be able to successfully decode the parts that
// it knows and have access to the rest.
func TestMibUploadNextResponseRelaxedDecode(t *testing.T) {
	// Test msg has OLT-G ME that normally only has 4 attributes defined. Since several are
	// pretty big and would normally take at least 3 MIB upload next frames.  So in
	// this one it has the last 'known' one, plus two new ones.
	extraTrailer := "123400001234000000000000"
	goodAttribute := "123456780a090807060504030201"
	mibUploadNextLayer := "00020000008300001c00" + goodAttribute + extraTrailer
	goodMessage := "02862e0a" + mibUploadNextLayer + "00000028"

	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	extraTrailerData, _ := stringToPacket(extraTrailer)
	assert.NotNil(t, extraTrailerData)

	mibUploadNextLayerData, _ := stringToPacket(mibUploadNextLayer)
	assert.NotNil(t, mibUploadNextLayerData)

	goodAttributeData, _ := stringToPacket(goodAttribute)
	assert.NotNil(t, goodAttributeData)

	// Make sure relaxed decode is disabled
	assert.NoError(t, me.SetRelaxedDecode(me.MibUploadNext, false, false))
	assert.False(t, me.GetRelaxedDecode(me.MibUploadNext, false))

	// Should get a packet but there should also be an error layer after the OMCI layer
	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)

	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, BaselineIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(40), omciMsg.Length)

	// Without relaxed decode, the MIB Upload Next Response cannot be decoded further
	// but can get the error layer and it's contents (which is the entire MIB Upload Response data
	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.Nil(t, msgLayer)

	errLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, errLayer)
	assert.Nil(t, errLayer.LayerPayload())
	errContents := errLayer.LayerContents()
	assert.NotNil(t, errContents)
	assert.Equal(t, mibUploadNextLayerData, errContents)

	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	// Now turn on relaxed decode and you can now go further into the packet
	assert.NoError(t, me.SetRelaxedDecode(me.MibUploadNext, false, true))
	assert.True(t, me.GetRelaxedDecode(me.MibUploadNext, false))

	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer = packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok = omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)

	// Skipping the test of OMCI layer values. It is same as above
	//
	// Get that message layer that has data that could be decoded. If relaxed decode was
	// not enable, this would have returned a 'nil' value
	msgLayer = packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.CanDecode())
	assert.Equal(t, me.OltGClassID, response.ReportedME.GetClassID())
	assert.Equal(t, uint16(0), response.ReportedME.GetEntityID())

	// The attribute mask decoded at this layer only contains the attributes we
	// could successfully decode
	assert.Equal(t, uint16(0x1000), response.ReportedME.GetAttributeMask())

	attributes := me.AttributeValueMap{
		"TimeOfDayInformation": goodAttributeData, // NOTE: This is binary data for the comparison below
	}
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, pktValue, value)
	}
	assert.Nil(t, response.AdditionalMEs)

	////////////////////////////////////////////////////////////////////////////
	// Here is the new functionality.  In order to store both a well decoded
	// MIB UPLOAD NEXT response layer, along with a relaxed decode error, the
	// layer addition has to be done in a specific way and an error returned.
	//
	//     Note that the previous line (below) worked in the code above
	//
	//           response, ok2 := msgLayer.(*MibUploadNextResponse)
	//
	// If you did not care about what the relaxed decode found out, just proceed
	// on as normal.  However, since you enabled relaxed decoding of the unknown
	// attributes, here is where you can pull extra information from.
	//
	//  The first way is to just try and see if that error layer was decoded
	//
	//      if unknownAttrLayer = packet.Layer(LayerTypeUnknownAttributes); unknownAttrLayer != nil {
	//          log.warning(HEY! Got some unknown attributes to this ME: '%v', unknownAttrLayer)
	//
	//          unknownAttributes, ok2 := msgLayer.(*UnknownAttributes); ok {
	//				//
	//				// Since some extended messages can actually return multiple managed entities,
	//              // all ME's with unknown attributes need to be uniquely identified
	//              //
	//              for _, unknown := range unknownAttibutes.Attributes {
	//                  whichME     := unknown.EntityClass			// ClassID
	//                  whichInst   := unknown.EntityInstance		// uint16
	//					unknownMask := unknown.AttributeMask		// uint16
	//					unknownBlob := unknown.Attributes			// []byte
	//
	//                  // Unless this is the extended message set and only a single attribute
	//              	// mask bit is set, you really do not know what possible kind of data
	//              	// type the attribute is...
	//               }
	//	         }
	//       }
	/////////////////////////////////////
	assert.NotEqual(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, LayerTypeUnknownAttributes, response.NextLayerType())

	unknownAttrLayer := packet.Layer(LayerTypeUnknownAttributes)
	assert.NotNil(t, unknownAttrLayer)

	unknown, ok2 := unknownAttrLayer.(*UnknownAttributes)
	assert.True(t, ok2)
	assert.NotNil(t, unknown)
	assert.Equal(t, LayerTypeUnknownAttributes, unknown.LayerType())
	assert.Equal(t, LayerTypeUnknownAttributes, unknown.CanDecode())
	assert.Equal(t, gopacket.LayerTypeZero, unknown.NextLayerType())

	// Only one Managed entity was in this response and had a bad attribute
	assert.Equal(t, 1, len(unknown.Attributes))
	assert.Equal(t, me.OltGClassID, unknown.Attributes[0].EntityClass)
	assert.Equal(t, uint16(0), unknown.Attributes[0].EntityInstance)
	assert.Equal(t, uint16(0x0c00), unknown.Attributes[0].AttributeMask)
	assert.Equal(t, extraTrailerData, unknown.Attributes[0].AttributeData)
}

// TestMibUploadNextResponseExtendedRelaxedDecode is the extended message
// set test of the test above (just one Managed Entity)
func TestMibUploadNextResponseExtendedRelaxedDecode(t *testing.T) {
	// Test msg has OLT-G ME that normally only has 4 attributes defined. Since several are
	// pretty big and would normally take at least 3 MIB upload next frames.  So in
	// this one it has the last 'known' one, plus two new ones.
	extraTrailer := "123400001234"                  // 6 octets
	goodAttribute := "123456780a090807060504030201" // 14 octets
	mibUploadNextLayer := "00020000" + "001c" +
		"0014" +
		"008300001c00" + // 6 octets
		goodAttribute + extraTrailer // 14 + 6 octets
	goodMessage := "02862e0b" + mibUploadNextLayer

	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	extraTrailerData, _ := stringToPacket(extraTrailer)
	assert.NotNil(t, extraTrailerData)

	mibUploadNextLayerData, _ := stringToPacket(mibUploadNextLayer)
	assert.NotNil(t, mibUploadNextLayerData)

	goodAttributeData, _ := stringToPacket(goodAttribute)
	assert.NotNil(t, goodAttributeData)

	// Make sure relaxed decode is disabled
	assert.NoError(t, me.SetRelaxedDecode(me.MibUploadNext, false, false))
	assert.False(t, me.GetRelaxedDecode(me.MibUploadNext, false))

	// Should get a packet but there should also be an error layer after the OMCI layer
	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)

	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(28), omciMsg.Length)

	// Without relaxed decode, the MIB Upload Next Response cannot be decoded further
	// but can get the error layer and it's contents (which is the entire MIB Upload Response data
	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.Nil(t, msgLayer)

	errLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, errLayer)
	assert.Nil(t, errLayer.LayerPayload())
	errContents := errLayer.LayerContents()
	assert.NotNil(t, errContents)
	assert.Equal(t, mibUploadNextLayerData, errContents)

	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	// Now turn on relaxed decode and you can now go further into the packet
	assert.NoError(t, me.SetRelaxedDecode(me.MibUploadNext, false, true))
	assert.True(t, me.GetRelaxedDecode(me.MibUploadNext, false))

	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer = packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok = omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)

	// Skipping the test of OMCI layer values. It is same as above
	//
	// Get that message layer that has data that could be decoded
	msgLayer = packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.CanDecode())
	assert.Equal(t, me.OltGClassID, response.ReportedME.GetClassID())
	assert.Equal(t, uint16(0), response.ReportedME.GetEntityID())

	// The attribute mask decoded at this layer only contains the attributes we
	// could successfully decode
	assert.Equal(t, uint16(0x1000), response.ReportedME.GetAttributeMask())

	attributes := me.AttributeValueMap{
		"TimeOfDayInformation": goodAttributeData, // NOTE: This is binary data for the comparison below
	}
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, pktValue, value)
	}
	////////////////////////////////////////////////////////////////////////////
	// Here is the new functionality.  In order to store both a well decoded
	// MIB UPLOAD NEXT response layer, along with a relaxed decode error, the
	// layer addition has to be done in a specific way and an error returned.
	//
	//     Note that the previous line (below) worked in the code above
	//
	//           response, ok2 := msgLayer.(*MibUploadNextResponse)
	//
	// If you did not care about what the relaxed decode found out, just proceed
	// on as normal.  However, since you enabled relaxed decoding of the unknown
	// attributes, here is where you can pull extra information from.
	//
	//  The first way is to just try and see if that error layer was decoded
	//
	//      if unknownAttrLayer = packet.Layer(LayerTypeUnknownAttributes); unknownAttrLayer != nil {
	//          log.warning(HEY! Got some unknown attributes to this ME: '%v', unknownAttrLayer)
	//
	//          unknownAttributes, ok2 := msgLayer.(*UnknownAttributes); ok {
	//				//
	//				// Since some extended messages can actually return multiple managed entities,
	//              // all ME's with unknown attributes need to be uniquely identified
	//              //
	//              for _, unknown := range unknownAttibutes.Attributes {
	//                  whichME     := unknown.EntityClass			// ClassID
	//                  whichInst   := unknown.EntityInstance		// uint16
	//					unknownMask := unknown.AttributeMask		// uint16
	//					unknownBlob := unknown.Attributes			// []byte
	//
	//                  // Unless this is the extended message set and only a single attribute
	//              	// mask bit is set, you really do not know what possible kind of data
	//              	// type the attribute is...
	//               }
	//	         }
	//       }
	/////////////////////////////////////
	assert.NotEqual(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, LayerTypeUnknownAttributes, response.NextLayerType())

	unknownAttrLayer := packet.Layer(LayerTypeUnknownAttributes)
	assert.NotNil(t, unknownAttrLayer)

	unknown, ok2 := unknownAttrLayer.(*UnknownAttributes)
	assert.True(t, ok2)
	assert.NotNil(t, unknown)
	assert.Equal(t, LayerTypeUnknownAttributes, unknown.LayerType())
	assert.Equal(t, LayerTypeUnknownAttributes, unknown.CanDecode())
	assert.Equal(t, gopacket.LayerTypeZero, unknown.NextLayerType())

	// Only one Managed entity was in this response and had a bad attribute
	assert.Equal(t, 1, len(unknown.Attributes))
	assert.Equal(t, me.OltGClassID, unknown.Attributes[0].EntityClass)
	assert.Equal(t, uint16(0), unknown.Attributes[0].EntityInstance)
	assert.Equal(t, uint16(0x0c00), unknown.Attributes[0].AttributeMask)
	assert.Equal(t, uint16(0x0c00), unknown.Attributes[0].AttributeMask)
	assert.Equal(t, extraTrailerData, unknown.Attributes[0].AttributeData)

}

// TestMibUploadNextResponseExtendedRelaxedDecode is the extended message
// set test of the test above (with two Managed Entity where both have bad attributes)
func TestMibUploadNextResponseExtendedRelaxedDecodeTwoMEs(t *testing.T) {
	// Test msg has OLT-G ME that normally only has 4 attributes defined. Since several are
	// pretty big and would normally take at least 3 MIB upload next frames.  So in
	// this one it has the last 'known' one, plus two new ones.
	extraTrailer1 := "123400001234"                 // 6 octets
	extraTrailer2 := "432100004321"                 // 6 octets
	goodAttribute := "123456780a090807060504030201" // 14 octets
	mibUploadNextLayer := "00020000" + "0038" +
		"0014" +
		"008300001c00" + // 6 octets
		goodAttribute + extraTrailer1 + // 14 + 6 octets
		"0014" +
		"008300011c00" + // 6 octets	(entity ID 1 which is invalid for OLT-g, but this is a test)
		goodAttribute + extraTrailer2 // 14 + 6 octets

	goodMessage := "02862e0b" + mibUploadNextLayer

	data, err := stringToPacket(goodMessage)
	assert.NoError(t, err)

	extraTrailerData1, _ := stringToPacket(extraTrailer1)
	assert.NotNil(t, extraTrailerData1)
	extraTrailerData2, _ := stringToPacket(extraTrailer2)
	assert.NotNil(t, extraTrailerData2)

	mibUploadNextLayerData, _ := stringToPacket(mibUploadNextLayer)
	assert.NotNil(t, mibUploadNextLayerData)

	goodAttributeData, _ := stringToPacket(goodAttribute)
	assert.NotNil(t, goodAttributeData)

	// Make sure relaxed decode is disabled
	assert.NoError(t, me.SetRelaxedDecode(me.MibUploadNext, false, false))
	assert.False(t, me.GetRelaxedDecode(me.MibUploadNext, false))

	// Should get a packet but there should also be an error layer after the OMCI layer
	packet := gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer := packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok := omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)

	assert.Equal(t, LayerTypeOMCI, omciMsg.LayerType())
	assert.Equal(t, LayerTypeOMCI, omciMsg.CanDecode())
	assert.Equal(t, LayerTypeMibUploadNextResponse, omciMsg.NextLayerType())
	assert.Equal(t, uint16(0x0286), omciMsg.TransactionID)
	assert.Equal(t, MibUploadNextResponseType, omciMsg.MessageType)
	assert.Equal(t, ExtendedIdent, omciMsg.DeviceIdentifier)
	assert.Equal(t, uint16(56), omciMsg.Length)

	// Without relaxed decode, the MIB Upload Next Response cannot be decoded further
	// but can get the error layer and it's contents (which is the entire MIB Upload Response data
	msgLayer := packet.Layer(LayerTypeMibUploadNextResponse)
	assert.Nil(t, msgLayer)

	errLayer := packet.Layer(gopacket.LayerTypeDecodeFailure)
	assert.NotNil(t, errLayer)
	assert.Nil(t, errLayer.LayerPayload())
	errContents := errLayer.LayerContents()
	assert.NotNil(t, errContents)
	assert.Equal(t, mibUploadNextLayerData, errContents)

	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	// Now turn on relaxed decode and you can now go further into the packet
	assert.NoError(t, me.SetRelaxedDecode(me.MibUploadNext, false, true))
	assert.True(t, me.GetRelaxedDecode(me.MibUploadNext, false))
	packet = gopacket.NewPacket(data, LayerTypeOMCI, gopacket.NoCopy)
	assert.NotNil(t, packet)

	omciLayer = packet.Layer(LayerTypeOMCI)
	assert.NotNil(t, omciLayer)

	omciMsg, ok = omciLayer.(*OMCI)
	assert.True(t, ok)
	assert.NotNil(t, omciMsg)

	// Skipping the test of OMCI layer values. It is same as above
	//
	// Get that message layer that has data that could be decoded
	msgLayer = packet.Layer(LayerTypeMibUploadNextResponse)
	assert.NotNil(t, msgLayer)

	response, ok2 := msgLayer.(*MibUploadNextResponse)
	assert.True(t, ok2)
	assert.NotNil(t, response)
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.LayerType())
	assert.Equal(t, LayerTypeMibUploadNextResponse, response.CanDecode())
	assert.Equal(t, me.OltGClassID, response.ReportedME.GetClassID())
	assert.Equal(t, uint16(0), response.ReportedME.GetEntityID())

	// The attribute mask decoded at this layer only contains the attributes we
	// could successfully decode
	assert.Equal(t, uint16(0x1000), response.ReportedME.GetAttributeMask())

	attributes := me.AttributeValueMap{
		"TimeOfDayInformation": goodAttributeData, // NOTE: This is binary data for the comparison below
	}
	for name, value := range attributes {
		pktValue, err := response.ReportedME.GetAttribute(name)
		assert.Nil(t, err)
		assert.Equal(t, pktValue, value)
	}
	// Now the second ME in the response
	assert.NotNil(t, response.AdditionalMEs)
	assert.Equal(t, 1, len(response.AdditionalMEs))

	////////////////////////////////////////////////////////////////////////////
	// Here is the new functionality.  In order to store both a well decoded
	// MIB UPLOAD NEXT response layer, along with a relaxed decode error, the
	// layer addition has to be done in a specific way and an error returned.
	//
	//     Note that the previous line (below) worked in the code above
	//
	//           response, ok2 := msgLayer.(*MibUploadNextResponse)
	//
	// If you did not care about what the relaxed decode found out, just proceed
	// on as normal.  However, since you enabled relaxed decoding of the unknown
	// attributes, here is where you can pull extra information from.
	//
	//  The first way is to just try and see if that error layer was decoded
	//
	//      if unknownAttrLayer = packet.Layer(LayerTypeUnknownAttributes); unknownAttrLayer != nil {
	//          log.warning(HEY! Got some unknown attributes to this ME: '%v', unknownAttrLayer)
	//
	//          unknownAttributes, ok2 := msgLayer.(*UnknownAttributes); ok {
	//				//
	//				// Since some extended messages can actually return multiple managed entities,
	//              // all ME's with unknown attributes need to be uniquely identified
	//              //
	//              for _, unknown := range unknownAttibutes.Attributes {
	//                  whichME     := unknown.EntityClass			// ClassID
	//                  whichInst   := unknown.EntityInstance		// uint16
	//					unknownMask := unknown.AttributeMask		// uint16
	//					unknownBlob := unknown.Attributes			// []byte
	//
	//                  // Unless this is the extended message set and only a single attribute
	//              	// mask bit is set, you really do not know what possible kind of data
	//              	// type the attribute is...
	//               }
	//	         }
	//       }
	/////////////////////////////////////
	assert.NotEqual(t, gopacket.LayerTypePayload, response.NextLayerType())
	assert.Equal(t, LayerTypeUnknownAttributes, response.NextLayerType())

	unknownAttrLayer := packet.Layer(LayerTypeUnknownAttributes)
	assert.NotNil(t, unknownAttrLayer)

	unknown, ok2 := unknownAttrLayer.(*UnknownAttributes)
	assert.True(t, ok2)
	assert.NotNil(t, unknown)
	assert.Equal(t, LayerTypeUnknownAttributes, unknown.LayerType())
	assert.Equal(t, LayerTypeUnknownAttributes, unknown.CanDecode())
	assert.Equal(t, gopacket.LayerTypeZero, unknown.NextLayerType())

	// Only one Managed entity was in this response and had a bad attribute
	assert.Equal(t, 2, len(unknown.Attributes))
	assert.Equal(t, me.OltGClassID, unknown.Attributes[0].EntityClass)
	assert.Equal(t, uint16(0), unknown.Attributes[0].EntityInstance)
	assert.Equal(t, uint16(0x0c00), unknown.Attributes[0].AttributeMask)
	assert.Equal(t, extraTrailerData1, unknown.Attributes[0].AttributeData)

	assert.Equal(t, me.OltGClassID, unknown.Attributes[1].EntityClass)
	assert.Equal(t, uint16(1), unknown.Attributes[1].EntityInstance)
	assert.Equal(t, uint16(0x0c00), unknown.Attributes[1].AttributeMask)
	assert.Equal(t, extraTrailerData2, unknown.Attributes[1].AttributeData)

	errStr := unknown.Error()
	assert.NotNil(t, errStr)
	assert.Greater(t, len(errStr.Error()), 0)
}

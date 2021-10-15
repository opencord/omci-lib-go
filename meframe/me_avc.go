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

package meframe

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

func AttributeValueChangeFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &AttributeValueChangeMsg{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		AttributeMask: 0,
		Attributes:    make(me.AttributeValueMap),
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)
	payloadAvailable := int(maxPayload) - 2 // Less attribute mask

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload, payloadAvailable)
	return meLayer, errors.New("todo: Not implemented")
}

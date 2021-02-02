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

// ClassSupport specifies the support for this Managed Entity by the ONU
type ClassSupport int

const (
	UnknownSupport     = iota
	Supported          // Supported as defined by this object
	Unsupported        // OMCI returns error code if accessed
	PartiallySupported // some aspects of ME supported
	Ignored            // OMCI supported, but underlying function is now

	// The following two are specific unsupported Managed Entity Definitions
	UnsupportedManagedEntity               // Unsupported ITU G.988 Class ID
	UnsupportedVendorSpecificManagedEntity // Unsupported Vendor Specific Class ID
)

func (cs ClassSupport) String() string {
	return [...]string{"Unknown", "Supported", "Unsupported", "Partially Supported", "Ignored",
		"Unsupported", "Vendor Specific"}[cs]
}

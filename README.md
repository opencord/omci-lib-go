# OMCI

OMCI gopacket library supports the encoding and decoding of ITU G.988 OMCI
messages.  Support for the Baseline Message Set has been completed and work
is underway to support the Extended Message Set format.

## Message Types supported and under unit test
The following OMCI message types currently have been coded and are covered
satisfactory by unit tests.

 - CreateRequest
 - CreateResponse
 - DeleteRequest
 - DeleteResponse
 - SetRequest
 - GetRequest
 - GetAllAlarmsRequest
 - GetAllAlarmsResponse
 - GetAllAlarmsNextRequest
 - MibUploadRequest
 - MibUploadResponse
 - MibUploadNextRequest
 - MibResetRequest
 - MibResetResponse
 - SynchronizeTimeRequest
 - DownloadSectionRequest
 - DownloadSectionResponse
 - EndSoftwareDownloadRequest
 - EndSoftwareDownloadResponse
 - CommitSoftwareRequest
 - CommitSoftwareResponse
 - AlarmNotification

## Message Types supported but lacking full unit test
The following OMCI message types currently have been coded and are partially covered
by unit tests, but work still remains for sufficient/better unit test coverage.

 - SetResponse
 - GetResponse
 - GetAllAlarmsNextResponse
 - MibUploadNextResponse
 - SynchronizeTimeResponse
 - AttributeValueChange
 - RebootRequest
 - RebootResponse
 - StartSoftwareDownloadRequest
 - GetNextRequest
 - GetNextResponse
 - TestResult
 - TestRequest
 - TestResponse

## Message Types supported but lacking any unit test
The following OMCI message types currently have been coded but do not
have any unit test coverage.

 - StartSoftwareDownloadResponse
 - ActivateSoftwareRequest
 - ActivateSoftwareResponse
 - GetCurrentDataRequest
 - GetCurrentDataResponse
 
## Message Types not yet supported

The following OMCI message types currently have not been coded.

 - SetTableRequest
 - SetTableResponse

## Extended Message Set Support

As mentioned earlier, support for the Extended Message Set is underway.  Currently,
the following Message Types have this support and are covered by unit tests:

 - GetRequest
 - GetResponse

### Upcoming message types that will be supported

The following provides a list of message types that will eventually support the _Extended Message Set_
in the expected order of implementation.  The priority was chosen based on speed improvement requests
of operations and ease of implementation.

 - DownloadSectionRequest/Response
 - AlarmNotification
 - AttributeValueChange
 - TestResult

 - GetCurrentDataRequest/Response
 - MibResetRequest/Response
 - RebootRequest/Response
 - SynchronizeTimeRequest/Response
 - CreateRequest/Response
 - DeleteRequest/Response
 - SetRequest/Response
  
 - MibUploadRequest/Response
 - MibUploadNextRequest/Response
 - GetAllAlarmsRequest/Response
 - GetAllAlarmsNextRequest/Response
 - GetNextRequest/Response
  
 - StartSoftwareDownloadRequest/Response
 - EndSoftwareDownloadRequest/Response
 - CommitSoftwareRequest/Response
 - ActivateSoftwareRequest/Response
  
 - SetTableRequest/Response
 - TestRequest/Response

## Current user-test coverage

The _**make** test_ command can be used to create code coverage support for the
library.  The current coverage for version 1.0.0 (as of 4/21/2021) is:

| File            | Statement Coverage |
| --------------: | :---: |
| layers.go       | 100%  |
| mebase.go       | 91.7% |
| meframe.go      | 50.8% |
| messagetypes.go | 59.1% |
| omci.go         | 79.0% |

## Other outstanding items

Besides OMCI Message decode/serialization, and associated unit tests, the following items
would be needed or useful in a first official release of this library. Some changes are
to be done in the generated OMCI ME code as well.

 - Constraint checking (these are not yet fully parsed/provided by the OMCI code generated
   structs). This feature will hopefully be available in the near future.
 - Add AVC flag for appropriate attributes
 - Add some type of logging support
 
Also searching through the code for _TODO_ statements will also yield additional areas of
work to be performed.

## What is not provided by this library

This library is not a full OMCI stack for either an OLT or an ONU. It is focused primarily on
packet decode/serialization and a variety of structs and functions that are useful for handling
the creation of OMCI frames and handling decoded frames from the PON.

For an OLT-side OMCI stack, you would still need to write:
 - OMCI CC sender & receiver (stop & wait protocol) with appropriate timeout support
 - OLT State machines to support 
   - MIB Uploads/Audits/Resynchronization (and a MIB database implemention),
   - More sophisticated get & get-next support to make handle of MEs with
     lots of attributes or table attributes easy to handle and code,
   - Alarm Table support,
   - OMCI ME/Msg-Type capabilities inquiry,
   - Performance Monitoring collection (and initial time synchronization), 
   - Service implementation

For an ONU-side OMCI stack, you would still need to write:
   - OMCC implementation,
   - MIB Database,
   - Get-Next cache for table attributes,
   - MIB upload next cache for MIB uploads,
   - Generation of any alarms/AVC notifications,
   - Actually acting on the create/delete/get/set/... requests from an OLT
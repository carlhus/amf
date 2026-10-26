package ngap

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// ngSetupRequestNRLEOHex is free-ran-ue's NG Setup Request for a gNB configured
// with ratInformation NR_LEO (gnb/ngapBuilder_test.go keeps the same bytes).
const ngSetupRequestNRLEOHex = "00150038000004001b00080002f83910000314005240050100674e42" +
	"0066001700400000010002f83900001008010203000000b30001800015400140"

func TestNGSetupRequestRATInformationSetsUeRatType(t *testing.T) {
	servedTai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	unknownTai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000002"}

	testCases := []struct {
		name                string
		stripRATInformation bool
		tai                 models.Tai
		expectRatType       models.RatType
	}{
		{name: "RAT Information NR_LEO", tai: servedTai, expectRatType: models.RatType_NR_LEO},
		{name: "no RAT Information", stripRATInformation: true, tai: servedTai, expectRatType: models.RatType_NR},
		{name: "TAI not in Supported TA List", tai: unknownTai, expectRatType: models.RatType_NR},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			NewAmfContext(amf_context.GetSelf())
			amf_context.GetSelf().Name = "AMF"
			conn := new(ngaptesting.SctpConnStub)
			ran := &amf_context.AmfRan{
				Conn: conn,
				Log:  logger.NgapLog.WithField(logger.FieldRanAddr, "127.0.0.1"),
			}
			ran.SupportedTAList = make([]amf_context.SupportedTAI, 0, amf_context.MaxNumOfTAI)

			encoded, err := hex.DecodeString(ngSetupRequestNRLEOHex)
			require.NoError(t, err)
			decoded, err := ngapMessage.Parse(encoded)
			require.NoError(t, err)
			request, ok := decoded.(*ngapMessage.NGSetupRequest)
			require.True(t, ok)
			if test.stripRATInformation {
				request.SupportedTAList.List[0].IEExtensions = nil
			}

			dispatchMain(ran, request, encoded)

			require.Len(t, conn.MsgList, 1)
			response, err := ngapMessage.Parse(conn.MsgList[0])
			require.NoError(t, err)
			require.IsType(t, &ngapMessage.NGSetupResponse{}, response)
			require.Equal(t, test.expectRatType, ran.UeRatType(test.tai))
		})
	}
}

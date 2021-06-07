package cmd

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/onflow/cadence"
	jsoncdc "github.com/onflow/cadence/encoding/json"

	"github.com/onflow/flow-go/model/bootstrap"
	"github.com/onflow/flow-go/state/protocol/inmem"
	"github.com/onflow/flow-go/utils/io"
	"github.com/onflow/flow-go/utils/unittest"
)

const happyPathLogs = `^read in root-protocol-snapshot.json` +
	`extracted resetEpoch transaction arguments from snapshot` +
	`wrote resetEpoch transaction arguments`

var happyPathRegex = regexp.MustCompile(happyPathLogs)

// TestResetHappyPathWithoutPayout tests that given the root snapshot file and no payout, the command
// writes file containing the correct argument values
func TestResetHappyPathWithoutPayout(t *testing.T) {

	unittest.RunWithTempDir(t, func(bootDir string) {

		nodesPerCluster := 5

		// to match regex
		hook := zeroLoggerHook{logs: &strings.Builder{}}
		log = log.Hook(hook)

		// path to args file (if created)
		path, err := os.Getwd()
		require.NoError(t, err)
		argsPath := filepath.Join(path, resetArgsFileName)

		// remove args file once test finishes
		defer func() {
			err := os.Remove(argsPath)
			require.NoError(t, err)
		}()

		// create a root snapshot
		rootSnapshot := unittest.RootSnapshotFixture(unittest.IdentityListFixture(nodesPerCluster))

		// write snapshot to correct path in bootDir
		err = writeRootSnapshot(bootDir, rootSnapshot)
		require.NoError(t, err)

		// set initial flag values
		flagBootDir = bootDir
		flagPayout = ""

		// run command
		resetRun(nil, nil)
		require.Regexp(t, happyPathRegex, hook.logs.String())

		// check if args file was created
		require.FileExists(t, argsPath)

		// read file and make sure values are exactly as expected
		var resetEpochArgs []interface{}
		readJSON(argsPath, &resetEpochArgs)

		// extract args
		args := extractResetEpochArgs(rootSnapshot)
		verifyArguments(t, args, resetEpochArgs)
	})
}

// TestResetHappyPathWithPayout tests that given the root snapshot file and payout, the command
// writes file containing the correct argument values
func TestResetHappyPathWithPayout(t *testing.T) {

	unittest.RunWithTempDir(t, func(bootDir string) {

		nodesPerCluster := 5

		// to match regex
		hook := zeroLoggerHook{logs: &strings.Builder{}}
		log = log.Hook(hook)

		// path to args file (if created)
		path, err := os.Getwd()
		require.NoError(t, err)
		argsPath := filepath.Join(path, resetArgsFileName)

		// remove args file once test finishes
		defer func() {
			err := os.Remove(argsPath)
			require.NoError(t, err)
		}()

		// create a root snapshot
		rootSnapshot := unittest.RootSnapshotFixture(unittest.IdentityListFixture(nodesPerCluster))

		// write snapshot to correct path in bootDir
		err = writeRootSnapshot(bootDir, rootSnapshot)
		require.NoError(t, err)

		// set initial flag values
		flagBootDir = bootDir
		flagPayout = "10000.0"

		// run command
		resetRun(nil, nil)
		require.Regexp(t, happyPathRegex, hook.logs.String())

		// check if args file was created
		require.FileExists(t, argsPath)

		// read file and make sure values are exactly as expected
		var resetEpochArgs []interface{}
		readJSON(argsPath, &resetEpochArgs)

		// extract args
		args := extractResetEpochArgs(rootSnapshot)
		verifyArguments(t, args, resetEpochArgs)
	})
}

func verifyArguments(t *testing.T, expected []cadence.Value, actual []interface{}) {
	for index, arg := range actual {

		// marshal to bytes
		bz, err := json.Marshal(arg)
		require.NoError(t, err)

		// parse cadence value
		decoded, err := jsoncdc.Decode(bz)
		if err != nil {
			log.Fatal().Err(err).Msg("could not encode cadence arguments")
		}

		require.Equal(t, expected[index], decoded)
	}
}

func writeRootSnapshot(bootDir string, snapshot *inmem.Snapshot) error {
	rootSnapshotPath := filepath.Join(bootDir, bootstrap.PathRootProtocolStateSnapshot)
	return writeJSON(rootSnapshotPath, snapshot.Encodable())
}

// TODO: unify methods from all commands
// TODO: move this to common module
func writeJSON(path string, data interface{}) error {
	bz, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, bz, 0644)
	if err != nil {
		return err
	}

	return nil
}

// TODO: move this to common module
func readJSON(path string, target interface{}) {
	dat, err := io.ReadFile(path)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot read json")
	}
	err = json.Unmarshal(dat, target)
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot unmarshal json in file %s", path)
	}
}

// TODO: move this to common module
type zeroLoggerHook struct {
	logs *strings.Builder
}

func (h zeroLoggerHook) Run(_ *zerolog.Event, _ zerolog.Level, msg string) {
	h.logs.WriteString(msg)
}

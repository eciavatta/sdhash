package sdhash

import (
	"crypto/sha1"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"testing"
)

type testCase struct {
	name             string
	length           int64
	expectedErr      string
	fileName         string
	buffer           []byte
	compareSelfScore int
	compareSelfBfScore int
}

var testCases = []testCase{
	{
		name:        "zero-length",
		length:      0,
		expectedErr: "the length of buffer must be greater than 512",
	},
	{
		name:        "small",
		length:      256,
		expectedErr: "the length of buffer must be greater than 512",
	},
	{
		name:   "min-size-limit",
		length: 512,
	},
	{
		name:             "block-sized",
		length:           kB,
		compareSelfScore: 100,
		compareSelfBfScore: 0,
	},
	{
		name:             "rem-block",
		length:           kB*16 + 31,
		compareSelfScore: 100,
		compareSelfBfScore: 0,
	},
	{
		name:             "medium",
		length:           mB,
		compareSelfScore: 100,
		compareSelfBfScore: 0,
	},
	{
		name:             "large",
		length:           mB,
		compareSelfScore: 100,
		compareSelfBfScore: 0,
	},
	//{
	//	name: "very-large",
	//	length: 32*mB,
	//	compareSelfScore: 100,
	//},
}

func CreateSdbfTest(testName string, blockSize uint32, tmpDir string) func(t *testing.T) {
	return func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t1 *testing.T) {
				factory, err := CreateSdbfFromBytes(tc.buffer)
				var sd Sdbf
				if tc.expectedErr != "" && err != nil {
					assert.EqualError(t1, err, tc.expectedErr, tc.fileName)
				} else if err == nil {
					sdDigest, err := ioutil.ReadFile(fmt.Sprintf("testdata/%s/%s.sdbf", testName, tc.name))
					require.NoError(t1, err)

					sd = factory.WithBlockSize(blockSize * kB).WithName(tc.fileName).Compute()
					expected := fmt.Sprintf(string(sdDigest), len(tc.fileName), tc.fileName)
					assert.Equal(t1, expected, sd.String())
					assert.Equal(t1, tc.compareSelfScore, sd.Compare(sd))
				} else {
					require.Fail(t1, "invalid")
				}

				if sd != nil {
					bf := sd.GetIndex().(*bloomFilter)
					tmpFile := path.Join(tmpDir, fmt.Sprintf("%s-%s.idx", testName, tc.name))
					require.NoError(t1, bf.WriteToFile(tmpFile))

					bfFromIndexFileInt, err := NewBloomFilterFromIndexFile(tmpFile)
					require.NoError(t, err)
					bfFromIndexFile := bfFromIndexFileInt.(*bloomFilter)

					assert.Equal(t1, tc.compareSelfBfScore, bf.Compare(bf))

					assert.Equal(t1, sha1.Sum(bf.buffer), sha1.Sum(bfFromIndexFile.buffer))
					assert.Equal(t1, bf.hashCount, bfFromIndexFile.hashCount)
					assert.Equal(t1, bf.bitMask, bfFromIndexFile.bitMask)
					assert.Equal(t1, bf.compSize, bfFromIndexFile.compSize)
					assert.Equal(t1, bf.name, bfFromIndexFile.name)
					//assert.Equal(t1, tc.compareSelfBfScore, bf.Compare(bfFromIndexFile))

					bfFromStringInt, err := NewBloomFilterFromString(bf.String())
					assert.NoError(t1, err)
					bfFromString := bfFromStringInt.(*bloomFilter)

					assert.Equal(t1, sha1.Sum(bf.buffer), sha1.Sum(bfFromString.buffer))
					assert.Equal(t1, bf.hashCount, bfFromString.hashCount)
					assert.Equal(t1, bf.bitMask, bfFromString.bitMask)
					assert.Equal(t1, bf.compSize, bfFromString.compSize)
					assert.Equal(t1, bf.name, bfFromString.name)
					//assert.Equal(t1, tc.compareSelfBfScore, bf.Compare(bfFromString))
				}
			})
		}
	}
}

func TestGenericSdbf(t *testing.T) {
	require.DirExists(t, "testdata")

	tmpDir, err := ioutil.TempDir("", "sdhash-test")
	require.NoError(t, err)

	for i, tc := range testCases {
		r := rand.New(rand.NewSource(tc.length))
		buf := make([]byte, tc.length)
		n, err := r.Read(buf)
		require.Equal(t, tc.length, int64(n))
		require.NoError(t, err)

		fileName := path.Join(tmpDir, tc.name)
		require.NoError(t, ioutil.WriteFile(fileName, buf, 0664))
		testCases[i].fileName = fileName
		testCases[i].buffer = buf
	}

	t.Run("sdbf-stream", CreateSdbfTest("stream", 0, tmpDir))
	t.Run("sdbf-block1KB", CreateSdbfTest("block1kb", 1, tmpDir))
	t.Run("sdbf-block16KB", CreateSdbfTest("block16kb", 16, tmpDir))

	require.NoError(t, os.RemoveAll(tmpDir))
}

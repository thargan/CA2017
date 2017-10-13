using Enyim.Caching;
using NUnit.Framework;
using Ses.CaService.Models;
using System;
using System.Collections.Generic;
using System.Configuration;

namespace CaServiceTests
{
    [TestFixture]
    public class ElastiCacheTest
    {
        private ElastiCacheClient ecc;

        [SetUp]
        public void SetUp()
        {
            if (null == ecc)
            {
                ecc = ElastiCacheClientFactory.GetClient();
            }
            ecc.Flush();
        }

        [Test]
        public void testGetFromCacheEmpty()
        {
            string testKey = "testKey1";

            // Assert that we have no data for our test key
            byte[] emptyResult = ecc.Get(testKey);
            Assert.IsNull(emptyResult);
        }

        [Test]
        public void testAddByteArrayToCache()
        {
            string testKey = "testKey2";

            // Assert that we have no data for our test key
            byte[] emptyResult = ecc.Get(testKey);
            Assert.IsNull(emptyResult);

            // Instantiate a byte array and save it to the cache
            byte[] testValue = System.Text.Encoding.UTF8.GetBytes("My most excellent byte array test value");
            ecc.Set(testKey, testValue);

            byte[] cacheResult = ecc.Get(testKey);
            Assert.IsNotNull(cacheResult);
            Assert.AreEqual(testValue, cacheResult);
        }

        [Test]
        public void testRemoveFromCache()
        {
            // First, add some items to the cache
            string[] testKeys = new string[] { "testKey3", "testKey4" };
            string[] testValues = new string[] { "asdf1234", "fdsa4321" };

            for (int i = 0; i < testKeys.Length; i++)
            {
                byte[] testValue = System.Text.Encoding.UTF8.GetBytes(testValues[i]);
                ecc.Set(testKeys[i], testValue);
            }

            // For each key, assert that it exists, remove it, and assert that null is returned when fetched again
            for (int i = 0; i < testKeys.Length; i++)
            {
                byte[] validResult = ecc.Get(testKeys[i]);
                Assert.IsNotNull(validResult);
                ecc.Delete(testKeys[i]);
                byte[] emptyResult = ecc.Get(testKeys[i]);
                Assert.IsNull(emptyResult);
            }
        }

        [Test]
        public void testUseCacheSetting()
        {
            string trueKey = "UseAWSElastiCache";
            string falseKey = "UseCacheFalse";
            string undefinedKey = "ThisKeyDefinitelyDoesNotExistInTheConfigFile";

            bool expectTrue = getUseCacheBoolean(trueKey);
            bool expectFalse = getUseCacheBoolean(falseKey);
            bool expectFalseBecauseNull = getUseCacheBoolean(undefinedKey);

            Assert.IsTrue(expectTrue);
            Assert.IsFalse(expectFalse);
            Assert.IsFalse(expectFalseBecauseNull);
        }

        private bool getUseCacheBoolean(string configKey)
        {
            bool useCache = (null == ConfigurationManager.AppSettings[configKey])
                ? false
                : Boolean.Parse(ConfigurationManager.AppSettings[configKey]);

            return useCache;
        }
    }
}
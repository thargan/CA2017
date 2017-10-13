using Enyim.Caching;
using Enyim.Caching.Configuration;
using Enyim.Caching.Memcached;
using System;
using System.Configuration;
using System.Net;

namespace Ses.CaService.Caching
{
    public class MemcachedElastiCacheClient : ElastiCacheClient
    {
        private static readonly log4net.ILog _log = log4net.LogManager.GetLogger(typeof(MemcachedElastiCacheClient));

        private MemcachedClient _memcachedClient;

        public MemcachedElastiCacheClient() : this(Config.AwsElastiCacheUrl, Config.AwsElastiCachePort)
        { }

        public MemcachedElastiCacheClient(string url, int port)
        {
            try
            {
                MemcachedClientConfiguration config = new MemcachedClientConfiguration();
                config.Servers.Add(GetIPEndPointFromHostName(url, port, false));
                config.Protocol = MemcachedProtocol.Binary;
                _memcachedClient = new MemcachedClient(config);
            }
            catch(Exception ex)
            {
                _log.Error(string.Format("MemcachedElastiCacheClient CTOR Failure --> url: {0} --> port: {1}", url, port));
                _log.Error(ex);
                throw ex;
            }
        }

        private static IPEndPoint GetIPEndPointFromHostName(string url, int port, bool throwIfMoreThanOneIP)
        {
            var addresses = Dns.GetHostAddresses(url);
            if (addresses.Length == 0)
            {
                throw new ApplicationException("Unable to retrieve address from specified host name: " + url);
            }
            else if (throwIfMoreThanOneIP && addresses.Length > 1)
            {
                throw new ApplicationException("There is more that one IP address to the specified host name: " + url);
            }
            return new IPEndPoint(addresses[0], port); // Port gets validated here.
        }

        public override byte[] Get(string key)
        {
            try
            {
                return _memcachedClient.Get(key) as byte[];
            }
            catch (Exception e)
            {
                _log.Error("Cache Failure --> Exception Thrown: " + key, e);
                return null;
            }
        }

        public override bool Set(string key, byte[] value)
        {
            try
            {
                _memcachedClient.Store(StoreMode.Add, key, value);
                return true;
            }
            catch (Exception e)
            {
                _log.Error("Cache Failure --> Exception Thrown: " + key, e);
                return false;
            }
        }

        public override bool Delete(string key)
        {
            try
            {
                _memcachedClient.Remove(key);
                return true;
            }
            catch (Exception e)
            {
                _log.Error("Cache Failure --> Exception Thrown: " + key, e);
                return false;
            }
        }

        public override bool Flush()
        {
            try
            {
                _memcachedClient.FlushAll();
                return true;
            }
            catch (Exception e)
            {
                _log.Error("Cache Failure --> Exception Thrown", e);
                return false;
            }
        }
    }
}
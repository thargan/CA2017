using Enyim.Caching;
using Enyim.Caching.Configuration;
using Enyim.Caching.Memcached;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Web;

namespace Ses.CaService.Caching
{
    public static class ElastiCacheClientFactory
    {
        // https://github.com/enyim/EnyimMemcached/wiki/MemcachedClient-Usage

        private static ElastiCacheClient _activeClient = null;

        public enum ClientType
        {
            Memcached,
            Redis
        };

        public static ElastiCacheClient GetClient()
        {
            return GetClient(ClientType.Memcached);
        }

        public static ElastiCacheClient GetClient(ClientType clientType)
        {
            if (null == _activeClient)
            {
                switch (clientType)
                {
                    case ClientType.Memcached:
                    {
                        _activeClient = new MemcachedElastiCacheClient();
                        break;
                    }
                    case ClientType.Redis:
                    {
                        // TODO: Implement RedisElastiCacheClient
                        break;
                    }                    
                }
            }

            return _activeClient;
        }
    }
}
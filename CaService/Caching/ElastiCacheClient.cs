namespace Ses.CaService.Caching
{
    public abstract class ElastiCacheClient
    {
        public abstract byte[] Get(string key);

        public abstract bool Set(string key, byte[] value);

        public abstract bool Delete(string key);

        public abstract bool Flush();
    }
}
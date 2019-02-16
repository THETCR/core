// Copyright (c) 2012-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LEVELDBWRAPPER_H
#define BITCOIN_LEVELDBWRAPPER_H

#include "clientversion.h"
#include "serialize.h"
#include "streams.h"
#include <util/system.h>
#include "version.h"
#include <fs.h>

#include <boost/filesystem/path.hpp>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

static const size_t DBWRAPPER_PREALLOC_KEY_SIZE = 64;
static const size_t DBWRAPPER_PREALLOC_VALUE_SIZE = 1024;

class leveldb_error : public std::runtime_error
{
public:
    explicit leveldb_error(const std::string& msg) : std::runtime_error(msg) {}
};

class CLevelDBWrapper;

/** These should be considered an implementation detail of the specific database.
 */
namespace leveldbwrapper_private {

/** Handle database error by throwing dbwrapper_error exception.
 */
void HandleError(const leveldb::Status& status);

/** Work around circular dependency, as well as for testing in dbwrapper_tests.
 * Database obfuscation should be considered an implementation detail of the
 * specific database.
 */
const std::vector<unsigned char>& GetObfuscateKey(const CLevelDBWrapper &w);

};

/** Batch of changes queued to be written to a CLevelDBWrapper */
class CLevelDBBatch
{
    friend class CLevelDBWrapper;

private:
    leveldb::WriteBatch batch;

public:
    template <typename K, typename V>
    void Write(const K& key, const V& value)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(ssValue.GetSerializeSize(value));
        ssValue << value;
        leveldb::Slice slValue(&ssValue[0], ssValue.size());

        batch.Put(slKey, slValue);
    }

    template <typename K>
    void Erase(const K& key)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        batch.Delete(slKey);
    }
};
class CLevelDBIterator
{
private:
  const CLevelDBWrapper &parent;
  leveldb::Iterator *piter;

public:

  /**
   * @param[in] _parent          Parent CLevelDBWrapper instance.
   * @param[in] _piter           The original leveldb iterator.
   */
  CLevelDBIterator(const CLevelDBWrapper &_parent, leveldb::Iterator *_piter) :
      parent(_parent), piter(_piter) { };
  ~CLevelDBIterator();

  bool Valid() const;

  void SeekToFirst();

  template<typename K> void Seek(const K& key) {
      CDataStream ssKey(SER_DISK, CLIENT_VERSION);
      ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
      ssKey << key;
      leveldb::Slice slKey(ssKey.data(), ssKey.size());
      piter->Seek(slKey);
  }

  void Next();

  template<typename K> bool GetKey(K& key) {
      leveldb::Slice slKey = piter->key();
      try {
          CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
          ssKey >> key;
      } catch (const std::exception&) {
          return false;
      }
      return true;
  }

  template<typename V> bool GetValue(V& value) {
      leveldb::Slice slValue = piter->value();
      try {
          CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
          ssValue.Xor(leveldbwrapper_private::GetObfuscateKey(parent));
          ssValue >> value;
      } catch (const std::exception&) {
          return false;
      }
      return true;
  }

  unsigned int GetValueSize() {
      return piter->value().size();
  }

};

class CLevelDBWrapper
{
  friend const std::vector<unsigned char>& leveldbwrapper_private::GetObfuscateKey(const CLevelDBWrapper &w);
private:
    //! custom environment this database is using (may be NULL in case of default environment)
    leveldb::Env* penv;

    //! database options used
    leveldb::Options options;

    //! options used when reading from the database
    leveldb::ReadOptions readoptions;

    //! options used when iterating over values of the database
    leveldb::ReadOptions iteroptions;

    //! options used when writing to the database
    leveldb::WriteOptions writeoptions;

    //! options used when sync writing to the database
    leveldb::WriteOptions syncoptions;

    //! the database itself
    leveldb::DB* pdb;

  //! a key used for optional XOR-obfuscation of the database
  std::vector<unsigned char> obfuscate_key;

  //! the key under which the obfuscation key is stored
  static const std::string OBFUSCATE_KEY_KEY;

  //! the length of the obfuscate key in number of bytes
  static const unsigned int OBFUSCATE_KEY_NUM_BYTES;

  std::vector<unsigned char> CreateObfuscateKey() const;

public:
    CLevelDBWrapper(const fs::path& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CLevelDBWrapper();

    template <typename K, typename V>
    bool Read(const K& key, V& value) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            leveldbwrapper_private::HandleError(status);
        }
        try {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template <typename K, typename V>
    bool Write(const K& key, const V& value, bool fSync = false)
    {
        CLevelDBBatch batch;
        batch.Write(key, value);
        return WriteBatch(batch, fSync);
    }

    template <typename K>
    bool Exists(const K& key) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            leveldbwrapper_private::HandleError(status);
        }
        return true;
    }

    template <typename K>
    bool Erase(const K& key, bool fSync = false)
    {
        CLevelDBBatch batch;
        batch.Erase(key);
        return WriteBatch(batch, fSync);
    }

    bool WriteBatch(CLevelDBBatch& batch, bool fSync = false);

    // not available for LevelDB; provide for compatibility with BDB
    bool Flush()
    {
        return true;
    }

    bool Sync()
    {
        CLevelDBBatch batch;
        return WriteBatch(batch, true);
    }

    CLevelDBIterator *NewIterator()
    {
        return new CLevelDBIterator(*this, pdb->NewIterator(iteroptions));
    }
};

#endif // BITCOIN_LEVELDBWRAPPER_H

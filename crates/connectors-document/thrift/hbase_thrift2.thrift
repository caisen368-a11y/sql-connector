/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Wire-compatible subset of Apache HBase 2.6.3 thrift2/hbase.thrift.
namespace rs hbase_thrift2

struct TColumn {
  1: required binary family,
  2: optional binary qualifier,
  3: optional i64 timestamp
}

struct TColumnValue {
  1: required binary family,
  2: required binary qualifier,
  3: required binary value,
  4: optional i64 timestamp,
  5: optional binary tags,
  6: optional byte type
}

struct TResult {
  1: optional binary row,
  2: required list<TColumnValue> columnValues,
  3: optional bool stale = false,
  4: optional bool partial = false
}

enum TDeleteType {
  DELETE_COLUMN = 0,
  DELETE_COLUMNS = 1,
  DELETE_FAMILY = 2,
  DELETE_FAMILY_VERSION = 3
}

enum TDurability {
  USE_DEFAULT = 0,
  SKIP_WAL = 1,
  ASYNC_WAL = 2,
  SYNC_WAL = 3,
  FSYNC_WAL = 4
}

struct TGet {
  1: required binary row,
  2: optional list<TColumn> columns,
  5: optional i32 maxVersions,
  11: optional bool cacheBlocks
}

struct TPut {
  1: required binary row,
  2: required list<TColumnValue> columnValues,
  6: optional TDurability durability
}

struct TDelete {
  1: required binary row,
  2: optional list<TColumn> columns,
  4: optional TDeleteType deleteType = TDeleteType.DELETE_COLUMNS,
  7: optional TDurability durability
}

struct TScan {
  1: optional binary startRow,
  2: optional binary stopRow,
  3: optional list<TColumn> columns,
  4: optional i32 caching,
  5: optional i32 maxVersions = 1,
  11: optional bool reversed,
  12: optional bool cacheBlocks,
  15: optional i32 limit
}

struct TTableName {
  1: optional binary ns,
  2: required binary qualifier
}

struct TColumnFamilyDescriptor {
  1: required binary name,
  10: optional i32 maxVersions,
  11: optional i32 minVersions,
  13: optional i32 timeToLive,
  14: optional bool blockCacheEnabled,
  20: optional bool inMemory
}

struct TTableDescriptor {
  1: required TTableName tableName,
  2: optional list<TColumnFamilyDescriptor> columns,
  4: optional TDurability durability
}

exception TIOError {
  1: optional string message,
  2: optional bool canRetry
}

exception TIllegalArgument {
  1: optional string message
}

enum TThriftServerType {
  ONE = 1,
  TWO = 2
}

service THBaseService {
  bool exists(1: required binary table, 2: required TGet tget)
    throws (1: TIOError io),

  list<bool> existsAll(1: required binary table, 2: required list<TGet> tgets)
    throws (1: TIOError io),

  TResult get(1: required binary table, 2: required TGet tget)
    throws (1: TIOError io),

  void put(1: required binary table, 2: required TPut tput)
    throws (1: TIOError io),

  void putMultiple(1: required binary table, 2: required list<TPut> tputs)
    throws (1: TIOError io),

  void deleteSingle(1: required binary table, 2: required TDelete tdelete)
    throws (1: TIOError io),

  list<TResult> getScannerResults(
    1: required binary table,
    2: required TScan tscan,
    3: i32 numRows = 1
  ) throws (1: TIOError io),

  TTableDescriptor getTableDescriptor(1: required TTableName table)
    throws (1: TIOError io),

  list<TTableName> getTableNamesByPattern(
    1: optional string regex,
    2: required bool includeSysTables
  ) throws (1: TIOError io),

  TThriftServerType getThriftServerType(),

  string getClusterId()
}

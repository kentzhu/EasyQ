# 修改自 https://github.com/bdarnell/torndb/blob/master/torndb.py
# 解决原不兼容pymsyql的问题

import copy
import logging
import os
import time
import pymysql

class Connection(object):

    def __init__(self, host, db, 
                        user=None,
                        password=None,
                        port=3306,
                        charset = "utf8", 
                        sql_mode="TRADITIONAL",
                        max_idle_time=7 * 3600,
                        **kwargs):
        self.host = host
        self.db = db
        self.max_idle_time=float(max_idle_time)
        args = dict(
            host=host,
            port=port,
            db=db,
            charset=charset,
            sql_mode=sql_mode,
            **kwargs
        )
        if user is not None:
            args["user"] = user
        if password is not None:
            args["password"] = password
        self._db = None
        self._db_args = args
        self._last_use_time = time.time()
        try:
            self.reconnect()
        except Exception:
            logging.error("Cannot connect to MySQL on %s", self.host, exc_info=True)

    def __del__(self):
        self.close()

    def close(self):
        if getattr(self, "_db", None) is not None:
            self._db.close()
            self._db = None
    
    def reconnect(self):
        self.close()
        self._db = pymysql.connect(**self._db_args)
        self._db.autocommit(True)


    def query(self,query,*parameters,**kwparameters):
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters, kwparameters)
            column_names = [d[0] for d in cursor.description]
            return [Row(zip(column_names, row)) for row in cursor]
        finally:
            cursor.close()

    def get(self, query, *parameters, **kwparameters):
        rows = self.query(query, *parameters, **kwparameters)
        if not rows:
            return None
        elif len(rows) > 1:
            raise Exception("Multiple rows returned for Database.get() query")
        else:
            return rows[0]

    def execute(self, query, *parameters, **kwparameters):
        """Executes the given query, returning the lastrowid from the query."""
        return self.execute_lastrowid(query, *parameters, **kwparameters)
    
    def execute_lastrowid(self, query, *parameters, **kwparameters):
        """Executes the given query, returning the lastrowid from the query."""
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters, kwparameters)
            return cursor.lastrowid
        finally:
            cursor.close()

    def execute_rowcount(self, query, *parameters, **kwparameters):
        """Executes the given query, returning the rowcount from the query."""
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters, kwparameters)
            return cursor.rowcount
        finally:
            cursor.close()


    def executemany(self, query, parameters):
        """Executes the given query against all the given param sequences.
        We return the lastrowid from the query.
        """
        return self.executemany_lastrowid(query, parameters)

    def executemany_lastrowid(self, query, parameters):
        """Executes the given query against all the given param sequences.
        We return the lastrowid from the query.
        """
        cursor = self._cursor()
        try:
            cursor.executemany(query, parameters)
            return cursor.lastrowid
        finally:
            cursor.close()

    def executemany_rowcount(self, query, parameters):
        """Executes the given query against all the given param sequences.
        We return the rowcount from the query.
        """
        cursor = self._cursor()
        try:
            cursor.executemany(query, parameters)
            return cursor.rowcount
        finally:
            cursor.close()

    update = delete = execute_rowcount
    updatemany = executemany_rowcount

    insert = execute_lastrowid
    insertmany = executemany_lastrowid

    def _ensure_connected(self):
        if (self._db is None or
            (time.time() - self._last_use_time > self.max_idle_time)):
            self.reconnect()
        self._last_use_time = time.time()

    def _cursor(self):
        self._ensure_connected()
        return self._db.cursor()

    def _execute(self, cursor, query, parameters, kwparameters):
        try:
            return cursor.execute(query, kwparameters or parameters)
        except OperationalError:
            logging.error("Error connecting to MySQL on %s", self.host)
            self.close()
            raise


class Row(dict):
    """A dict that allows for object-like property access syntax."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)



# Fix the access conversions to properly recognize unicode/binary
FIELD_TYPE = pymysql.constants.FIELD_TYPE
FLAG = pymysql.constants.FLAG
CONVERSIONS = copy.copy(pymysql.converters.conversions)

field_types = [FIELD_TYPE.BLOB, FIELD_TYPE.STRING, FIELD_TYPE.VAR_STRING]
if 'VARCHAR' in vars(FIELD_TYPE):
    field_types.append(FIELD_TYPE.VARCHAR)

#for field_type in field_types:
#    CONVERSIONS[field_type] = [(FLAG.BINARY, str)] + CONVERSIONS[field_type]

# Alias some common MySQL exceptions
IntegrityError = pymysql.IntegrityError
OperationalError = pymysql.OperationalError
package org.wineav.database;

public interface DatabaseListener {

	void databaseUpdated(Database db, UpdateMode mode);
	
}

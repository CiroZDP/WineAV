package org.wineav.database;

import java.io.*;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.wineav.util.Utils;

public class Database implements Cloneable {

	public final Set<String> hashes = new HashSet<>();
	private DatabaseListener listener = null;
	
	public Database(Set<String> hashes) {
		this.hashes.addAll(hashes);
	}

	public Database(Database other) {
		this(other.hashes);
	}

	public Database() {
	}

	public static Database empty() {
		return new Database();
	}
	
	public static Database of(Set<String> hashes) {
		return new Database(hashes);
	}

	public static Database clone(Database db) {
		return new Database(db);
	}

	public static Database load(File file) throws FileNotFoundException, IOException {
		try {
			var reader = new BufferedReader(new FileReader(file));
			Database db = new Database();

			String sHash = null;
			while ((sHash = reader.readLine()) != null) {
				db.mergeSignedSHA(sHash);
			}

			reader.close();
			return db;
		} catch (FileNotFoundException fnfe) {
			throw new FileNotFoundException("Database doesn't exists!");
		}
	}

	public static Database load(Path path) throws FileNotFoundException, IOException {
		return load(path.toFile());
	}

	public void setListener(DatabaseListener listener) {
		this.listener = listener;
		listener.databaseUpdated(this, UpdateMode.INIT);
	}
	
	public int amountOfHashes() {
		return hashes.size();
	}

	public void save(File file) throws FileNotFoundException, IOException {
		if (!file.exists())
			file.createNewFile();

		var fos = new FileOutputStream(file);
		var dos = new DataOutputStream(fos);

		for (String sha : hashes)
			dos.writeBytes('+' + Utils.b16t64(sha) + '\n');

		dos.close();
	}

	public void save(Path path) throws IOException {
		this.save(path.toFile());
		if (listener != null)
			listener.databaseUpdated(this, UpdateMode.SAVE);
	}

	public void clearHashes() {
		this.hashes.clear();
		if (listener != null)
			listener.databaseUpdated(this, UpdateMode.REMOVE);
	}
	
	public void addHash(String hash) {
		this.hashes.add(hash);
		if (listener != null)
			listener.databaseUpdated(this, UpdateMode.ADD);
	}
	
	public void removeHash(String hash) {
		this.hashes.remove(hash);
		if (listener != null)
			listener.databaseUpdated(this, UpdateMode.REMOVE);
	}
	
	public static Database merge(Database db1, Database db2) {
		Database cdb1 = Database.clone(db1);
		for (String hash : db2.hashes)
			cdb1.mergeSHA('+', Utils.b16t64(hash));
		
		return cdb1;
	}

	public void mergeSignedSHA(String signedb64SHA) {
		char sign = signedb64SHA.charAt(0);
		signedb64SHA = signedb64SHA.substring(1);
		mergeSHA(sign, signedb64SHA);
	}

	public void mergeSHA(char sign, final String b64SHA) {
		final boolean addmode = sign != '-';

		if (addmode)
			addHash(Utils.b64t16(b64SHA));
		else
			removeHash(Utils.b64t16(b64SHA));
		
		if (listener != null)
			listener.databaseUpdated(this, UpdateMode.MERGE);
	}

	public Database clone() {
		return Database.clone(this);
	}
}

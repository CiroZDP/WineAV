package org.wineav.checking;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

import org.wineav.database.*;

public final class SHAChecker implements DatabaseListener {

	private static final SHAChecker INSTANCE = new SHAChecker();
	private Set<String> hashList = null;

	private SHAChecker() {
	}

	public static SHAChecker getInstance() {
		return INSTANCE;
	}

	public SHAChecker setHashList(Set<String> hashList) {
		this.hashList = hashList;
		return this;
	}

	public SHAChecker readDatabase(Database db) {
		return setHashList(db.hashes);
	}

	public Checksum scan(File f) {
		boolean malware = false;
		int status = 0;

		String hash = null;

		try {
			hash = getFileHash(Paths.get(f.toURI()));
		} catch (Exception ignored) {
			status = 1;
		}

		malware = hashList.contains(hash);
		return new Checksum(
				hash,
				status,
				malware ? MalwareType.MALWARE : MalwareType.NO_MALWARE
			);

	}
	
	public static String getFileHash(Path filePath) throws IOException, NoSuchAlgorithmException {
		byte[] data = Files.readAllBytes(filePath);
		byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(data);
		
		return new BigInteger(1, hashBytes).toString(16);
	}

	@Override
	public void databaseUpdated(Database db, UpdateMode mode) {
		readDatabase(db);
	}

}

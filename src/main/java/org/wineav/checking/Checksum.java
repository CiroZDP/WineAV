package org.wineav.checking;

public final class Checksum {

	private final String hash;
	private final int status;
	private final MalwareType type;
	
	public Checksum(String hash, int status, MalwareType malwareType) {
		this.hash = hash;
		this.status = status;
		this.type = malwareType == null ? MalwareType.NO_MALWARE : malwareType;
	}

	public MalwareType getType() {
		return type;
	}
	
	public String getHash() {
		return hash;
	}
	
	public int getStatus() {
		return status;
	}

	public boolean hasFailed() {
		return status != 0;
	}

	public void print() {
		System.out.println("   Contains malware: " + (type.containsMalware() ? "Yes" : "No"));
		System.out.println("   Malware type: " + type);
		System.out.println("   File hash: " + hash);
		System.out.println("   Status: " + (status == 0 ? "Successful" : "Failed"));
		
	}
	
}

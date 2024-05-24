package org.wineav;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.Map.Entry;

import org.wineav.checking.Checksum;
import org.wineav.checking.SHAChecker;
import org.wineav.database.Database;

public class Main {

	private final SHAChecker checker = SHAChecker.getInstance();
	private Database database = null;
	private Path databasePath = null;

	public void run() throws Exception {
		this.database = Database.empty();

		this.checker.readDatabase(database);
		this.database.setListener(checker);

		// Create a database and ask the user to input virus hashes
		int option = 0;
		do {
			option = requestOption();

			switch (option) {

				case 1:
					Scanner sc = new Scanner(System.in);
					System.out.print("Insert file path: ");
					Path filePath = null;
					try {
						filePath = Paths.get(sc.nextLine());
					} catch (Exception ex) {
						ex.printStackTrace();
						break;
					}

					System.out.println();
					if (filePath.toString().equalsIgnoreCase("Cancel")) {
						System.out.println("Operation Cancelled!");
						break;
					}

					if (!filePath.toFile().exists()) {
						System.err.println("File doesn't exists!");
						break;
					}

					if (database.amountOfHashes() == 0) {
						System.out.println("INFO: No available hashes to compare the file to!");
						break;
					}

					var checksum = checker.scan(filePath.toFile());
					System.out.println("Checksum:");
					checksum.print();

					break;
				case 2:
					sc = new Scanner(System.in);
					System.out.print("Insert the hash: ");
					String hash = sc.nextLine();

					this.database.addHash(hash);
					System.out.println("\nHash added!");
					break;

				case 3:
					sc = new Scanner(System.in);
					System.out.print("Insert the hash: ");
					hash = sc.nextLine();
					this.database.removeHash(hash);

					System.out.println("\nHash removed!");
					break;

				case 4:
					reviewHashes(this.database);
					break;

				case 5:
					if (databasePath == null) {
						System.err.println("ERROR: No database location specified!");
						break;
					} else if (!databasePath.toFile().exists()) {
						databasePath.toFile().createNewFile();
					}

					Database db = Database.load(databasePath);
					reviewHashes(db);
					break;

				case 6:
					if (databasePath == null) {
						System.err.println("ERROR: No database location specified!");
						break;
					}

					this.database.save(databasePath);
					System.out.println("Database saved successfully!");
					break;

				case 7:
					if (databasePath == null) {
						System.err.println("ERROR: No database location specified!");
						break;
					}

					this.database = Database.load(databasePath);
					this.database.setListener(checker);
					System.out.println("Database loaded successfully!");
					break;

				case 8:
					sc = new Scanner(System.in);
					System.out.print("New database location: ");
					this.databasePath = Paths.get(sc.nextLine());
					System.out.println("Database location changed successfully!");
					break;

				case 9:
					System.out.print("Database status: ");

					if (databasePath == null) {
						System.out.println("Not specified");
						break;
					}

					if (databasePath.toFile().exists()) {
						System.out.print("FINE");
						db = Database.load(databasePath);
						System.out.println(" - " + db.amountOfHashes() + " Hashes");
						break;
					} else {
						System.out.println("Not exists");
					}
					break;

				case 10:
					sc = new Scanner(System.in);
					System.out.print("Insert database path to merge: ");
					Path odp = Paths.get(sc.nextLine());

					if (odp.toString().equalsIgnoreCase("Cancel")) {
						System.out.println("Operation Cancelled!");
						break;
					}

					db = Database.load(odp);
					System.out.println("Merging...");
					this.database = Database.merge(database, db);
					this.database.setListener(checker);

					System.out.println("Merged successfully!");
					System.out.println();
					System.out.println("NOTE: You can select option 4 to see current hashes");
					break;

				case 11:
					sc = new Scanner(System.in);
					System.out.print("Insert file path: ");
					try {
						filePath = Paths.get(sc.nextLine());
					} catch (Exception ex) {
						ex.printStackTrace();
						break;
					}

					if (filePath.toString().equalsIgnoreCase("Cancel")) {
						System.out.println("Operation Cancelled!");
						break;
					}

					if (!filePath.toFile().exists()) {
						System.err.println("File doesn't exists!");
						break;
					}

					this.database.addHash(SHAChecker.getFileHash(filePath));
					System.out.println("File marked as malicious!");
					break;

				case 12:
					this.database.clearHashes();
					System.out.println("Hashes cleared!");
					break;

				case 13:
					sc = new Scanner(System.in);
					System.out.print("Insert file path: ");
					try {
						filePath = Paths.get(sc.nextLine());
					} catch (Exception ex) {
						ex.printStackTrace();
						break;
					}

					if (filePath.toString().equalsIgnoreCase("Cancel")) {
						System.out.println("Operation Cancelled!");
						break;
					}

					if (!filePath.toFile().exists()) {
						System.err.println("File doesn't exists!");
						break;
					}

					this.database.removeHash(SHAChecker.getFileHash(filePath));
					System.out.println("File unmarked!");
					break;

				case 14:
					sc = new Scanner(System.in);
					System.out.print("Insert directory path: ");
					Path dirPath = Paths.get(sc.nextLine());
					
					if (dirPath.toString().equalsIgnoreCase("Cancel")) {
						System.out.println("Operation Cancelled!");
						break;
					}
					
					File dir = dirPath.toFile();
					if (!dir.exists()) {
						System.out.println("The directory doesn't exists!");
						System.out.println("No folder to scan, skipping...");
						break;
					}
					
					scanDirectory(dir);
					break;
					
				case -1:
				default:
					System.err.println("Unrecognized option!");
				case 0:
			}
		} while (option != 0);
	}

	private synchronized void scanDirectory(File dir) {
		if (!dir.isDirectory()) {
			new IOException("Not a directory!").printStackTrace();
			return;
		}
	
		Map<File, Checksum> checksums = new HashMap<>();
		
		File[] files = dir.listFiles();
		for (File file : files) {
			if (file.isFile()) {
				checksums.put(file, this.checker.scan(file));
				System.out.println(" Scanned " + file.getAbsolutePath());
			} else {
				scanDirectory(file);
			}
		}
		
		var entries = checksums.entrySet();
		for (Entry<File, Checksum> entry : entries) {
			Checksum ck = entry.getValue();
			if (ck.getType().containsMalware()) {
				System.out.println();
				System.out.println("Checksum of " + entry.getKey().getAbsolutePath() + ":");
				ck.print();
			}
		}
	}

	private static int requestOption() {
		System.out.println();
		System.out.print("Option: ");
		try {
			@SuppressWarnings("resource")
			int option = new Scanner(System.in).nextInt();
			return option;
		} catch (Exception ignored) {
		}

		return -1;
	}

	private static void reviewHashes(Database db) {
		if (db.amountOfHashes() == 0) {
			System.out.println("No hashes detected!");
			return;
		}

		System.out.println("Hashes:");
		db.hashes.stream().forEach(hash -> System.out.println("> " + hash));
	}

	public static void main(String[] args) throws Exception {
		System.out.println(" ==== WINEAV SIBERMATICA ====");
		System.out.println("   1. Scan a file");
		System.out.println("   2. Add hash");
		System.out.println("   3. Remove hash");
		System.out.println("   4. See stored hashes");
		System.out.println("   5. See saved hashes");
		System.out.println("   6. Save database");
		System.out.println("   7. Load database / Discard changes");
		System.out.println("   8. Change database location");
		System.out.println("   9. Lockup status");
		System.out.println("  10. Merge databases");
		System.out.println("  11. Mark file as malicious");
		System.out.println("  12. Clear hashes");
		System.out.println("  13. Unmark malicious file");
		System.out.println("  14. Scan directory");
		System.out.println("   0. Quit");
		new Main().run();
	}

}

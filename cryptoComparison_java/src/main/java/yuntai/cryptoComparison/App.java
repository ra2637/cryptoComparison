package yuntai.cryptoComparison;

import java.security.InvalidParameterException;
import java.security.Security;

import oracleJCE.Algos;

public class App {
	public enum LIB {
		JCE, BC
	};

	public enum ALGORITHM {
		DES, AES, RSA, DH, SHA512, MD5
	};

	public enum MODE {
		CBC, OFB
	}

	private static String provider = "SunJCE";

	/**
	 * 
	 * @param args
	 *            File LIB Algorithm Mode
	 */
	public static void main(String[] args) {
		if (args.length < 3) {
			throw new InvalidParameterException("Insufficient parameters: File LIB Algorithm Mode");
		}

		String filePAth = args[0];
		LIB lib = LIB.valueOf(args[1]);
		ALGORITHM algo = ALGORITHM.valueOf(args[2]);
		MODE mode = null;

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		if (lib.equals(LIB.BC)) {
			provider = "BC";
		}
		switch (algo) {
		case DES:
			mode = MODE.valueOf(args[3]);
			Algos.symmetric(filePAth, algo, mode);
			break;
		case AES:
			mode = MODE.valueOf(args[3]);
			Algos.symmetric(filePAth, algo, mode);
			break;
		case DH:
			Algos.DH(filePAth);
			break;
		case RSA:
			Algos.RSA(filePAth);
			break;
		case SHA512:
			Algos.hash(filePAth, algo);
			break;
		case MD5:
			Algos.hash(filePAth, algo);
			break;
		default:
			break;
		}
	}

	public static String getProvider() {
		return provider;
	}
}

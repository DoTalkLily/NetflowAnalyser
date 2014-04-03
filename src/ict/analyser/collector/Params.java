package ict.analyser.collector;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.Date;

public abstract class Params {
	public static boolean v9TemplateOverwrite = false;

	public static boolean template_refreshFromHD = false;

	public static boolean ip2ipsConvert = true;

	public static boolean DEBUG = false;

	public static String encoding = "GBK";

	public static String path = null;// like "D:\Dev\workspace\netflow\bin"

	static {
		path = Params.class.getProtectionDomain().getCodeSource().getLocation()
				.getFile();
		try {
			path = URLDecoder.decode(path, "UTF-8");
		} catch (UnsupportedEncodingException e) {
		}

		File directory = new File(path);

		if (path.trim().toLowerCase().endsWith(".jar")) {
			directory = directory.getParentFile();
		}
		try {
			path = directory.getCanonicalPath();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	static SimpleDateFormat f = new SimpleDateFormat("yyyyMMddHHmmss");

	public static String getCurrentTime() {
		return f.format(new Date());
	}
}

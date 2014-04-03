package ict.analyser.netflow;

import ict.analyser.tools.Resources;

import java.util.HashMap;

public class TemplateManager {

	private Template v5Template = null;

	private static TemplateManager mgr = new TemplateManager();

	private static String v5FileName = null;

	private Resources resources = new Resources("serverSampling");

	private HashMap<String, Template> mapTidTemplate = new HashMap<String, Template>();

	static {
		try {
			Class.forName("ict.analyser.collector.Collector");
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private TemplateManager() {
		try {
			v5FileName = "127.0.0.0_32.properties";
			v5Template = new Template(v5FileName);
			int sampleRate = resources.integer(v5Template.getRouterIp());
			if (sampleRate != 0) {
				v5Template.setSamplingRate(sampleRate);
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}
//
//		if (Params.template_refreshFromHD) {
//			File tpPath = new File(Template.templatePath);
//
//			if (tpPath.exists() && tpPath.isDirectory()) {
//				String[] fileNames = tpPath.list();
//
//				for (int idx = 0; idx < fileNames.length; idx++) {
//					Template t;
//					try {
//						if (fileNames[idx].indexOf(v5FileName) == -1) {
//							t = new Template(fileNames[idx]);
//							int samRate = resources.integer(t.getRouterIp());
//							if (samRate != 0) {
//								t.setSamplingRate(samRate);
//							}
//							mapTidTemplate.put(
//									t.getRouterIp() + "_" + t.getTemplateId(),
//									t);
//						}
//					} catch (Exception e) {
//						e.printStackTrace();
//					}
//				}
//			} else {
//				System.err.println("/etc/templates/ dose not exist");
//			}
//		}
	}

	public synchronized boolean acceptTemplate(String routerIp, byte[] content,
			int offset) {
		Exception ex = null;
		if (offset > 3) {
			Template t = null;
			try {
				t = new Template(routerIp, content, offset);
			} catch (Exception ex2) {
				ex = ex2;
			}

			int samRate = resources.integer(t.getRouterIp());
			if (samRate != 0) {
				t.setSamplingRate(samRate);
			}

			mapTidTemplate.put(t.getRouterIp() + "_" + t.getTemplateId(), t);

			if (ex != null) {
				ex.printStackTrace();
			}
			return true;
		}
		return false;
	}

	public synchronized Template getTemplate(String routerIp, int templateId) {
		return (Template) mapTidTemplate.get(routerIp + "_" + templateId);
	}

	public static synchronized TemplateManager getTemplateManager() {
		return mgr;
	}

	/**
	 * @return Returns the v5Template.
	 */
	public Template getV5Template() {
		return v5Template;
	}

	/**
	 * @param template
	 *            The v5Template to set.
	 */
	public void setV5Template(Template template) {
		v5Template = template;
	}
}

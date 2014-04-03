package ict.analyser.collector;

import ict.analyser.netflow.V5_Packet;
import ict.analyser.netflow.V9_Packet;
import ict.analyser.tools.IPTranslator;
import ict.analyser.tools.IpSegmentManager;
import ict.analyser.tools.Resources;
import ict.analyser.tools.Utils;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.NoSuchElementException;

public class Collector extends Thread {

	private long queued = 0;

	private long processed = 0;

	private static int localPort = 0;

	private static int sampleRate = 1;

	private static int max_queue_length = 0;

	private static int collector_thread = 0;

	private static final int MAX_VERION = 10;

	private static int receiveBufferSize = 0;

	private Aggregate aggregator = null;

	private static Resources resources = null;

	// private static SampleManager sampler = null;

	private static InetAddress localHost = null;

	private static boolean[] isVersionEnabled = null;

	private LinkedList<DatagramPacket> data_queue = null;

	static {
		resources = new Resources("NetFlow");
		IpSegmentManager.getInstance();
		receiveBufferSize = resources.integer("net.receive.buffer.size");
		localPort = resources.integer("net.bind.port");

		String local = resources.get("net.bind.host");
		Params.v9TemplateOverwrite = resources
				.isTrue("flow.collector.V9.template.overwrite");// 是否在接收到相同ip和template
																// id的模板时覆盖已经缓存的
		Params.template_refreshFromHD = resources
				.isTrue("flow.collector.template.refreshFromHD");// 是否根据动态接收template报文生成properties
		Params.ip2ipsConvert = resources.isTrue("flow.ip2ipsConvert");

		try {
			localHost = InetAddress.getLocalHost();
		} catch (UnknownHostException e) {
			localHost = null;
		}

		if (localHost == null) {
			resources.error("unknown host `" + local + "'");
		}
		// }

		isVersionEnabled = new boolean[MAX_VERION];
		isVersionEnabled[0] = resources.isTrue("flow.collector.V5.enabled");
		isVersionEnabled[1] = resources.isTrue("flow.collector.V9.enabled");

		max_queue_length = resources.integer("flow.collector.max_queue_length");
		collector_thread = resources.integer("flow.collector.collector.thread");

		if (collector_thread < 1) {
			resources.error("key `" + collector_thread + "' bust be great one");
		}

		// 采集端控制采集率
		// sampler = new SampleManager(sampleRate);
	}

	public Collector() {
		sampleRate = resources.integer("sample.rate");
		if (sampleRate == 0) {
			sampleRate = 1;
		}
		aggregator = new Aggregate();
		data_queue = new LinkedList<DatagramPacket>();
	}

	/**
	 * 
	 *
	 */
	@Override
	public void run() {
		go();
	}

	void go() {
		// 一个采集线程
		ServiceThread collecter = new ServiceThread(this, "Reader at "
				+ (localHost == null ? "any" : "" + localHost) + ":"
				+ localPort, "Reader") {
			public void exec() throws Throwable {
				((Collector) o).reader_loop();
			}
		};

		collecter.setPriority(Thread.MAX_PRIORITY);
		collecter.setDaemon(true);
		collecter.start();

		// 分析线程
		ServiceThread[] collectors = new ServiceThread[collector_thread];

		for (int i = 0; i < collector_thread; i++) {
			String title = new String("Collector #" + (i + 1));
			ServiceThread collector = new ServiceThread(this, title, title) {
				public void exec() {
					((Collector) o).collector_loop();
				}
			};
			collectors[i] = collector;
			collector.start();
		}

		try {
			for (int i = 0; i < collector_thread; i++) {
				collectors[i].join();// 等待每个分析线程结束
				System.out.println("collector is finished!");
			}
		} catch (InterruptedException e) {
			System.err
					.println("Collector - InterruptedException in main thread, exit");
		}
	}

	/**
	 * 
	 * 
	 * @throws Throwable
	 */
	public void reader_loop() throws Throwable {

		DatagramSocket socket = null;

		try {
			socket = new DatagramSocket(55888, localHost);
			socket.setReceiveBufferSize(receiveBufferSize);
		} catch (IOException exc) {
			System.err.println("Reader - socket create error: " + localHost);
			throw exc;
		}

		while (true) {
			// byte[] buf = new byte[2048];
			byte[] buf = new byte[1000];
			DatagramPacket packet = null;

			if (packet == null) {
				packet = new DatagramPacket(buf, buf.length);

				try {
					socket.receive(packet);
				} catch (IOException exc) {
					exc.printStackTrace();
					put_to_queue(null);// ��ʾnotifyAll
					break;
				}
			}
			// if (this.sampler.shouldDue()) {
			put_to_queue(packet);
			// }
			packet = null;
		}
	}

	void put_to_queue(final DatagramPacket packet) {

		if (data_queue.size() > max_queue_length)
			System.out
					.println("Reader - the queue is bigger then max_queue_length "
							+ data_queue.size() + "/" + max_queue_length);

		synchronized (data_queue) {
			data_queue.addLast(packet);
			queued++;
			// System.out.println("queued : " + queued);
			if (packet == null)
				data_queue.notifyAll();
			else
				data_queue.notify();
		}
	}

	void collector_loop() {
		boolean no_data = true;

		while (true) {
			Object p = null;

			synchronized (data_queue) {
				try {
					if (data_queue.getFirst() != null) {
						p = data_queue.removeFirst();
						// System.out.println("processed : ");
					}
					no_data = false;
				} catch (NoSuchElementException ex) {
				}
			}

			if (no_data) {
				synchronized (data_queue) {
					try {
						data_queue.wait();
					} catch (InterruptedException e) {
					}
				}
			} else {
				no_data = true;

				if (p == null)
					break;

				processPacket((DatagramPacket) p);
			}
		}
	}

	private synchronized void processPacket(final DatagramPacket p) {
		final byte[] buf = p.getData();
		int len = p.getLength();
		String addr = p.getAddress().getHostAddress();

		// p.getAddress().getAddress();

		synchronized (data_queue) {
			processed++;
		}

		if (len < 2) {
			System.err.println(" * Too short packet  *");
			return;
		}

		short version = (short) Utils.byte2long(buf, 0, 2);

		if (version > MAX_VERION || version <= 0) {
			System.err.println("  * Unsupported version *");
			return;
		}

		if (version == 5 && !isVersionEnabled[0]) {
			System.err.println(" * Version 5 is not enabled! *");
			return;
		}

		if (version == 9 && !isVersionEnabled[1]) {
			System.err.println(" * Version 9 is not enabled! *");
			return;
		}

		V5_Packet v5Packet = null;
		V9_Packet v9Packet = null;

		long routerIp = IPTranslator.calIPtoLong(addr);

		switch (version) {
		case 5:
			v5Packet = new V5_Packet(routerIp, buf, len);
			aggregator.process(v5Packet);
			break;
		case 9:
			v9Packet = new V9_Packet(routerIp, buf, len);
			aggregator.process(v9Packet);
			break;
		default:
			System.err.println("Collector - BUG: Version problem, version="
					+ version);
			return;
		}

	}

	/**
	 * @return Returns the queued.
	 */
	public long getQueued() {
		return queued;
	}

	/**
	 * @return Returns the processed.
	 */
	public long getProcessed() {
		return processed;
	}

}

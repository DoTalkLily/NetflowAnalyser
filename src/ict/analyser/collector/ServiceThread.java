package ict.analyser.collector;

public abstract class ServiceThread extends Thread {

	protected Object o;

	private String start, stop;

	public ServiceThread(Object o, String start, String stop) {
		this.o = o;
		this.start = start;
		this.stop = stop;
	}

	public void run() {
		System.out.println("START: " + getName() + ", " + this.start);

		try {
			exec();
		} catch (Throwable e) {
			e.printStackTrace();
		}

		System.out.println("STOP: " + getName() + ", " + this.stop);
	}

	public abstract void exec() throws Throwable;
}

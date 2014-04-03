package ict.analyser.tools;

public class SampleManager {
	int sampleRate = 1;
	int currValue = 0;
	public SampleManager(int rate){
		sampleRate=rate;
	}
	boolean shouldDue(){
		currValue++;
		if (currValue>=sampleRate){
			currValue=0;
			return true;
		}
		return false;
	}
	/**
	 * @return Returns the sampleRate.
	 */
	public int getSampleRate() {
		return sampleRate;
	}
	/**
	 * @param sampleRate The sampleRate to set.
	 */
	public void setSampleRate(int sampleRate) {
		this.sampleRate = sampleRate;
	}
}

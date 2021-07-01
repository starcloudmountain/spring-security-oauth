import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

public class LoopRule implements TestRule {
	
	private int loopCount;

    public LoopRule(int loopCount) {
        this.loopCount = loopCount;
    }

	@Override
	public Statement apply(final Statement base, Description description) {
		return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                for (int i = 1; i <= loopCount; i++) {
                    System.out.println("Loop " + i + " started");
                    base.evaluate();
                    System.out.println("Loop " + i + " finished\n----------------");
                }
            }
        };
	}

}

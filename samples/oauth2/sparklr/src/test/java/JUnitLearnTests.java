import java.io.IOException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.Timeout;

public class JUnitLearnTests {
	// 使用系统临时目录，可在构造方法上加入路径参数来指定临时目录
	@Rule  
	public TemporaryFolder tempFolder = new TemporaryFolder();
	
	@Rule
    public Timeout timeout = new Timeout(1000);
	
	@Rule
    public LoopRule loopRule = new LoopRule(2);
	
	private boolean isRunning=true;
	
	// Run once, e.g. Database connection, connection pool
    @BeforeClass
    public static void runOnceBeforeClass() {
        System.out.println("@BeforeClass - runOnceBeforeClass");
    }
    
    // Run once, e.g close connection, cleanup
    @AfterClass
    public static void runOnceAfterClass() {
        System.out.println("@AfterClass - runOnceAfterClass");
    }
    
    @Before
    public void runBeforeTestMethod() {
        System.out.println("@Before - runBeforeTestMethod");
    }
    
    @After
    public void runAfterTestMethod() {
        System.out.println("@After - runAfterTestMethod");
    }
	
	@Test
    public void testSayHello() {
        System.out.println("helloWorld");
    }
	  
	@Test  
	public void testTempFolderRule() throws IOException { 
		System.out.println("testTempFolderRule");
		
		if(isRunning){
		    // 在系统的临时目录下创建文件或者目录，当测试方法执行完毕自动删除  
		    tempFolder.newFile("test.txt");  
		    tempFolder.newFolder("test");  
		    
		    this.isRunning=false;
		}
	}
	
	// 测试失败
    @Test
    public void test1() throws Exception {
    	System.out.println("test1");
    	
        Thread.sleep(1000);
    }
    
    // 测试成功
    @Test
    public void test2() throws Exception {
    	System.out.println("test2");

        Thread.sleep(444);
    }
}

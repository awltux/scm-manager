package sonia.scm.api.v2.resources;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;
import sonia.scm.repository.HgConfig;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class HgConfigDtoToHgConfigMapperTest {

  @InjectMocks
  private HgConfigDtoToHgConfigMapperImpl mapper;

  @Test
  public void shouldMapFields() {
    HgConfigDto dto = createDefaultDto();
    HgConfig config = mapper.map(dto);

    assertTrue(config.isDisabled());

    assertEquals("ABC", config.getEncoding());
    assertEquals("/etc/hg", config.getHgBinary());
    assertEquals("/py", config.getPythonBinary());
    assertEquals("/etc/", config.getPythonPath());
    assertTrue(config.isShowRevisionInId());
    assertTrue(config.isUseOptimizedBytecode());
    assertTrue(config.isDisableHookSSLValidation());
    assertTrue(config.isEnableHttpPostArgs());
  }

  private HgConfigDto createDefaultDto() {
    HgConfigDto configDto = new HgConfigDto();
    configDto.setDisabled(true);
    configDto.setEncoding("ABC");
    configDto.setHgBinary("/etc/hg");
    configDto.setPythonBinary("/py");
    configDto.setPythonPath("/etc/");
    configDto.setShowRevisionInId(true);
    configDto.setUseOptimizedBytecode(true);
    configDto.setDisableHookSSLValidation(true);
    configDto.setEnableHttpPostArgs(true);

    return configDto;
  }
}

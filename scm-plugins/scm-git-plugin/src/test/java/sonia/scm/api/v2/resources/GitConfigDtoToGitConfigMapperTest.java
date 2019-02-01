package sonia.scm.api.v2.resources;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;
import sonia.scm.repository.GitConfig;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class GitConfigDtoToGitConfigMapperTest {

  @InjectMocks
  private GitConfigDtoToGitConfigMapperImpl mapper;

  @Test
  public void shouldMapFields() {
    GitConfigDto dto = createDefaultDto();
    GitConfig config = mapper.map(dto);
    assertEquals("express", config.getGcExpression());
    assertFalse(config.isDisabled());
    assertTrue(config.isNonFastForwardDisallowed());
  }

  private GitConfigDto createDefaultDto() {
    GitConfigDto gitConfigDto = new GitConfigDto();
    gitConfigDto.setGcExpression("express");
    gitConfigDto.setDisabled(false);
    gitConfigDto.setNonFastForwardDisallowed(true);
    return gitConfigDto;
  }
}

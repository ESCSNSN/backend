package com.example.esclogin.dto;

import lombok.*;
import org.antlr.v4.runtime.misc.NotNull;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString

public class UserSuspendDTO {
    @NotBlank(message = "Username is mandatory")
    private String username;

    @NotNull
    private Boolean suspend;

    private String reason;
    private LocalDateTime suspendedUntil;

}

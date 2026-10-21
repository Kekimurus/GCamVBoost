package gcam.edgetpu

import app.morphe.patcher.extensions.InstructionExtensions.getInstruction
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.patch.booleanOption
import app.morphe.patcher.patch.bytecodePatch
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.FieldReference

@Suppress("unused")
val magicCapturePatch = bytecodePatch(
    name = "Fix Magic Capture crash",
    description = "Bypasses EdgeTPU JNI native initialization in Magic Capture and falls back to CPU scoring to prevent SIGABRT crashes on non-stock signatures.",
    default = true
) {
    compatibleWith(
        "com.google.android.GoogleCameraEng",
        "com.google.android.GoogleCamera"
    )

    val patchAddMe by booleanOption(
        key = "patchAddMeEdgeTpu",
        default = true,
        title = "Also fix Add Me (All-In) EdgeTPU crash",
        description = "Forces DEVICE_UNSPECIFIED in the All-In TFLite person detector to prevent native SIGABRT crashes."
    )

    execute {
        // 1. Bypass PreFilteringPipelineImpl.h nativeCreate call
        val method = PreFilteringPipelineInitFingerprint.method
        val matches = PreFilteringPipelineInitFingerprint.instructionMatches

        val invokeNativeIndex = matches[0].index
        val moveResultWideIndex = matches[1].index

        val moveResultInst = method.getInstruction<OneRegisterInstruction>(moveResultWideIndex)
        val wideReg = moveResultInst.registerA

        // Replace `invoke-direct nativeCreate` and `move-result-wide` with `const-wide/16 vX, 0x0`
        // Setting native handle to 0L triggers Google Camera's internal graceful fallback path.
        method.replaceInstruction(
            invokeNativeIndex,
            "const-wide/16 v$wideReg, 0x0"
        )
        method.replaceInstruction(
            moveResultWideIndex,
            "nop"
        )

        // 2. Patch Add Me (Limc.<init>) if enabled
        if (patchAddMe == true) {
            val enumClinit = AllInDeviceEnumFingerprint.method
            val sputIndex = AllInDeviceEnumFingerprint.instructionMatches[2].index
            val deviceUnspecifiedField =
                enumClinit.getInstruction<ReferenceInstruction>(sputIndex).reference as FieldReference

            val configConstructor = AllInConfigConstructorFingerprint.method
            val configMatches = AllInConfigConstructorFingerprint.instructionMatches
            val moveResultIndex = configMatches[1].index
            val checkCastIndex = configMatches[2].index

            val targetReg = configConstructor.getInstruction<OneRegisterInstruction>(moveResultIndex).registerA

            configConstructor.replaceInstruction(
                moveResultIndex,
                "sget-object v$targetReg,$deviceUnspecifiedField"
            )
            configConstructor.replaceInstruction(
                checkCastIndex,
                "nop"
            )
        }
    }
}
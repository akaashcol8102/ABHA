import { Controller, Post, Body } from '@nestjs/common';
import { AadhaarService } from './aadhaar.service';

@Controller('aadhaar')
export class AadhaarController {
  constructor(private readonly aadhaarService: AadhaarService) {}

  @Post('enterAadhaar')
  async enterAadhaarNumber(@Body('aadhaarNumber') aadhaarNumber: string): Promise<any> {
    return this.aadhaarService.encryptAndGenerateOTP(aadhaarNumber);
  }

  @Post('verifyOtp')
  async verifyOtp(@Body('otp') otp: string, @Body('txnId') txnId: string): Promise<any> {
    return this.aadhaarService.verifyOtpAndGenerateMobileOtp(otp, txnId);
  }

  @Post('enterMobile')
  async enterMobileNumber(@Body('mobileNumber') mobileNumber: string, @Body('txnId') txnId: string): Promise<any> {
    return this.aadhaarService.generateMobileOtp(mobileNumber, txnId);
  }

  @Post('createHealthId')
  async createHealthId(@Body('txnId') txnId: string): Promise<any> {
    return this.aadhaarService.createHealthIdByAadhaar(txnId);
  }
}

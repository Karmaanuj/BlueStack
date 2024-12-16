from xml.dom import ValidationErr
from django.forms import ValidationError
from rest_framework import serializers
from IPOWebApp.utils import Util
from IPOWebApp.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class UserRegistrationSerializer(serializers.ModelSerializer):

    password2 = serializers.CharField(style={'input_type' : 'password'}, write_only = True)
    class Meta:
        model = User
        fields = ['email','name','password', 'password2', 'tc']
        extra_kwargs = {
            'password' : {'write_only' : True}
        }

    def validate(self, attrs):
        password = attrs.get('password') 
        password2 = attrs.get('password2') 

        if password != password2:
            raise serializers.ValidationError("Password not match")
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data )


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email' , 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style = {'input_type' : 'password'}, write_only = True)
    password2 = serializers.CharField(max_length = 255, style = {'input_type' : 'password'}, write_only = True)

    class Meta:
        fields = ['password', 'password2']
    
    def validate(self, attrs):
        password = attrs. get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and confirm password doesn't match")
        user.set_password(password)
        user.save()
        return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255)

    class Meta:
        fields = ['email']
    #email exist right email, only this email Authenticataion

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email) #take email object, user id genrate uid
            # uid = user.id  we do not user this it has to be encode 
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded Uid", uid)

            token = PasswordResetTokenGenerator().make_token(user)
            print('pasword reset token', token)

            # create link with help of token and uid 
            link = 'http://localhost:3000/changepassword/' + uid + '/' + token;
            print('Password reset link', link) 

            # Send email
            body = 'Click following link to reset your Password : ' + link
            data = {
                'subject' : 'Reset your password',
                'body' : body,
                'to_email' : user.email
            }
            Util.send_email(data)

            return attrs
        else:
            raise ValidationErr('You are not registered user')

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style = {'input_type' : 'password'}, write_only = True)
    password2 = serializers.CharField(max_length = 255, style = {'input_type' : 'password'}, write_only = True)

    class Meta:
        fields = ['password', 'password2']
    
    def validate(self, attrs):
       
       try : 
            
            password = attrs. get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and confirm password doesn't match")
        
             # Decode id to use
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
        
            # Chek token taken from link
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not Valid or Expired')
        
            user.set_password(password)
            user.save()
            return attrs

       except DjangoUnicodeDecodeError as identifier:
           PasswordResetTokenGenerator().check_token(user, token)
           raise ValidationError('Token is not Valid or Expired')





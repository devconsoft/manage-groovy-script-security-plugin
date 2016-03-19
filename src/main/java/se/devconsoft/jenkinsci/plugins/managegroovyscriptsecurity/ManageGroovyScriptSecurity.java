/*
 * The MIT License
 *
 * Copyright (c) 2016, DevConSoft, Per Böhlin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package se.devconsoft.jenkinsci.plugins.managegroovyscriptsecurity;

import hudson.model.*;
import hudson.Extension;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 *
 * The purpose of the class is to provide a white list to the
 * script security plugin to automatically white list all
 * groovy scripts. This is really bad for security and should
 * only be used on private jenkins instances.
 *
 */
@Extension
public class ManageGroovyScriptSecurity extends Whitelist implements Describable<ManageGroovyScriptSecurity> {

    public ManageGroovyScriptSecurity() {}

    @Extension
    public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

    public DescriptorImpl getDescriptor() {
        return DESCRIPTOR;
    }

    public static boolean isGroovyScriptSandboxSecurityDisabled() {
        return DESCRIPTOR.isGroovyScriptSandboxSecurityDisabled();
    }

    public static class DescriptorImpl extends Descriptor<ManageGroovyScriptSecurity> {

        private boolean disableGroovyScriptSandboxSecurity = false;

        public DescriptorImpl() {
            load();
        }

        @Override
        public String getDisplayName() {
            return "";
        }

        public boolean getGroovyScriptSandboxSecurityDisabled() {
            return this.disableGroovyScriptSandboxSecurity;
        }

        public boolean isGroovyScriptSandboxSecurityDisabled() {
            return this.disableGroovyScriptSandboxSecurity;
        }

        public void setGroovyScriptSandboxSecurityDisabled(boolean disableGroovyScriptSandboxSecurity) {
            this.disableGroovyScriptSandboxSecurity = disableGroovyScriptSandboxSecurity;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            disableGroovyScriptSandboxSecurity = formData.containsKey("disableGroovyScriptSandboxSecurity");
            save();
            return true;
        }
    }


    /*
     * Groovy Sandbox Security Whitelist implementation
     * By returning true to the whitelist methods, we allow execution
     * of scripts and hence bypass other security settings.
     */

    @Override
    public boolean permitsMethod(Method method, Object receiver, Object[] args) {
        return isGroovyScriptSandboxSecurityDisabled();
    }

    @Override
    public boolean permitsConstructor(Constructor<?> constructor, Object[] args) {
        return isGroovyScriptSandboxSecurityDisabled();
    }

    @Override
    public boolean permitsStaticMethod(Method method, Object[] args) {
        return isGroovyScriptSandboxSecurityDisabled();
    }

    @Override
    public boolean permitsFieldSet(Field field, Object receiver, Object value) {
        return isGroovyScriptSandboxSecurityDisabled();
    }

    @Override
    public boolean permitsFieldGet(Field field, Object receiver) {
        return isGroovyScriptSandboxSecurityDisabled();
    }

    @Override
    public boolean permitsStaticFieldSet(Field field, Object value) {
        return isGroovyScriptSandboxSecurityDisabled();
    }

    @Override
    public boolean permitsStaticFieldGet(Field field) {
        return isGroovyScriptSandboxSecurityDisabled();
    }

}
